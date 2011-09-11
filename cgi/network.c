/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#define OPENSSL_DISABLE_OLD_DES_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "argcargv.h"
#include "cosigncgi.h"
#include "conf.h"
#include "network.h"
#include "mkcookie.h"

static void (*logger)( char * ) = NULL;
static struct timeval		timeout = { 10 * 60, 0 };
extern int	errno;
extern char	*cosign_host;
extern SSL_CTX	*ctx;
int		cosign_protocol = 0;

static int connect_sn( struct connlist * );
static int cosign_choose_conn( struct connlist *, void *,
	int (*fp)( SNET *, void * ));
static int net_login( SNET *, void * );
static int net_logout( SNET *, void * );
static int net_register( SNET *, void * );
static int net_check( SNET *, void * );

/* not using this at present */
/* static int close_sn( struct connlist * ); */
    struct connlist *
connlist_setup( char *host, unsigned short port )
{

    int			i;
    struct hostent	*he;
    struct connlist	*head, *new, **tail;

    if (( he = gethostbyname( host )) == NULL ) {
        fprintf( stderr, "%s: gethostbyname() failed\n", host );
        return( NULL );
    }
    tail = &head;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
        if (( new = ( struct connlist * ) malloc( sizeof( struct connlist )))
		 == NULL ) {
            perror( "connlist build" );
	    return( NULL );
        }

        memset( &new->conn_sin, 0, sizeof( struct sockaddr_in ));
        new->conn_sin.sin_family = AF_INET;
        new->conn_sin.sin_port = port;
        memcpy( &new->conn_sin.sin_addr.s_addr,
                he->h_addr_list[ i ], (unsigned int)he->h_length );
        new->conn_sn = NULL;
        *tail = new;
        tail = &new->conn_next;   
    }
    *tail = NULL;

    return( head );

}

    static int
cosign_choose_conn( struct connlist *head, void *netparams,
	int (*fp)( SNET *, void * ))
{

    struct connlist 	*cur;
    int 		rc = 0, retry = 0;

    for ( cur = head; cur != NULL; cur = cur->conn_next ) {
        if ( cur->conn_sn == NULL ) {
            continue;
        }

        switch ( rc = (*fp)( cur->conn_sn, netparams )) {
	case COSIGN_OK :
	    return( 0 );

	case COSIGN_LOGGED_OUT :
	    return( -1 );

	case COSIGN_RETRY :
	    retry = 1;
	    break;

	default:
	    fprintf( stderr, "cosign_choose_conn: unknown return: %d", rc );

	case COSIGN_ERROR :
            if ( snet_close( cur->conn_sn ) != 0 ) {
                fprintf( stderr, "choose_conn: snet_close failed\n" );
            }
            cur->conn_sn = NULL;
	    break;
        }
    }

    /* all are closed or we didn't like their answer */
    for ( cur = head; cur != NULL; cur = cur->conn_next ) {
        if ( cur->conn_sn != NULL ) {
            continue;
        }
        if ( connect_sn( cur ) != 0 ) {
            continue;
        }

        switch ( rc = (*fp)( cur->conn_sn, netparams )) {
	case COSIGN_OK :
	    return( 0 );

	case COSIGN_LOGGED_OUT :
	    return( -1 );

	case COSIGN_RETRY :
	    retry = 1;
	    break;

	default:
	    fprintf( stderr, "cosign_choose_conn: unknown return: %d", rc );

	case COSIGN_ERROR :
            if ( snet_close( cur->conn_sn ) != 0 ) {
                fprintf( stderr, "choose_conn: snet_close failed\n" );
            }
            cur->conn_sn = NULL;
	    break;
        }
    }

    if ( retry ) {
	fprintf( stderr,
		"cosign_choose_conn: some servers returned UNKNOWN\n");
    } else {
	fprintf( stderr,
		"cosign_choose_conn: all servers returned ERROR\n");
    }
    return( -1 );
}

    int
cosign_login( struct connlist *conn, char *cookie, char *ip, char *user,
	char *realm, char *krb )
{
    struct login_param lp;

    if ( !validchars( cookie ) || !validuser( user )) {
	return( -1 );
    }

    lp.lp_cookie = cookie;
    lp.lp_ip = ip;
    lp.lp_user = user;
    lp.lp_realm = realm;
    lp.lp_krb = krb;

    if ( cosign_choose_conn( conn, &lp, net_login ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    static int
net_login( SNET *sn, void *vlp )
{
    int			fd = 0;
    ssize_t             rr, size = 0;
    char		*line;
    char		buf[ 8192 ];
    struct stat         st;
    struct timeval	tv;
    struct login_param	*lp = vlp;


    /* if we're doing BasicAuth or PAM we might not have a ticket */
    if ( lp->lp_krb == NULL ) {
	if ( snet_writef( sn, "LOGIN %s %s %s %s\r\n", lp->lp_cookie, lp->lp_ip,
		lp->lp_user, lp->lp_realm ) < 0 ) {
	    fprintf( stderr, "net_login: LOGIN failed\n" );
	    return( COSIGN_ERROR );
	}
    } else {
	if ( snet_writef( sn, "LOGIN %s %s %s %s kerberos\r\n", lp->lp_cookie,
		lp->lp_ip, lp->lp_user, lp->lp_realm ) < 0 ) {
	    fprintf( stderr, "net_login: LOGIN failed\n" );
	    return( COSIGN_ERROR );
	}
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "net_login: %s\n", strerror( errno ));
	return( COSIGN_ERROR );
    }

    if ( lp->lp_krb == NULL ) {
	/* skip ticket stuff */
	goto finish;
    }


    switch( *line ) {
    case '2':
	/* You'd only get this the user double clicks on the "login" button. */
	return( COSIGN_OK );

    case '3':
    	break;

    case '4':
        fprintf( stderr, "net_login: %s\n", line);
        return( COSIGN_LOGGED_OUT );

    case '5':
        /* choose another connection */
        return( COSIGN_RETRY );

    default:
        fprintf( stderr, "net_login: %s\n", line );
        return( COSIGN_ERROR );
    }

    if (( fd = open( lp->lp_krb, O_RDONLY, 0 )) < 0 ) {
	perror( lp->lp_krb );
	return( COSIGN_ERROR );
    }

    if ( unlink( lp->lp_krb ) != 0 ) {
	perror( lp->lp_krb );
	goto error;
    }

    if ( fstat( fd, &st) < 0 ) {
	perror( lp->lp_krb );
	goto error;
    }

    size = st.st_size;
    if ( snet_writef( sn, "%d\r\n", (int)st.st_size ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", lp->lp_user,
	    strerror( errno ));
        goto error;
    }

    while (( rr = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = timeout;
        if ( snet_write( sn, buf, rr, &tv ) != rr ) {
            fprintf( stderr, "login %s failed: %s\n", lp->lp_user,
                strerror( errno ));
            goto error;
        }
        size -= rr;
    }
    close( fd );
    if ( rr < 0 ) {
        perror( lp->lp_krb );
        return( COSIGN_ERROR );
    }

    /* Check number of bytes sent to server */
    if ( size != 0 ) {
        fprintf( stderr,
            "login %s failed: Sent wrong number of bytes to server\n",
            lp->lp_user );
        return( COSIGN_ERROR );
    }

    /* End transaction with server */
    if ( snet_writef( sn, ".\r\n" ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", lp->lp_user,
            strerror( errno ));
        return( COSIGN_ERROR );
    }
    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
        if ( snet_eof( sn )) {
            fprintf( stderr, "login %s failed: Connection closed\n",
		lp->lp_user );
        } else {
            fprintf( stderr, "login %s failed: %s\n",
		lp->lp_user, strerror( errno ));
        }

	goto error;
    }

finish:
    switch( *line ) {
    case '2':
	return( COSIGN_OK );

    case '4':
        fprintf( stderr, "net_login: %s\n", line);
        return( COSIGN_LOGGED_OUT );

    case '5':
        /* choose another connection */
        return( COSIGN_RETRY );

    default:
        fprintf( stderr, "net_login: %s\n", line );
        return( COSIGN_ERROR );
    }

error:
    close( fd );
    return( COSIGN_ERROR );
}

    int
cosign_logout( struct connlist *conn, char *cookie, char *ip )
{
    struct logout_param lp;

    if ( !validchars( cookie )) {
	return( -1 );
    }

    lp.lp_cookie = cookie;
    lp.lp_ip = ip;

    if ( cosign_choose_conn( conn, &lp, net_logout ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    static int
net_logout( SNET *sn, void *vlp )
{
    char		*line;
    struct timeval	 tv;
    struct logout_param	*lp = vlp;

    if ( snet_writef( sn, "LOGOUT %s %s\r\n", lp->lp_cookie, lp->lp_ip ) < 0 ) {
	fprintf( stderr, "net_logout: LOGOUT failed\n" );
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "net_logout: %s\n", strerror( errno ));
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	return( COSIGN_OK );

    case '4':
        fprintf( stderr, "net_logout: %s\n", line);
        return( COSIGN_LOGGED_OUT );

    case '5':
        /* choose another connection */
        return( COSIGN_RETRY );

    default:
        fprintf( stderr, "net_logout: %s\n", line );
        return( COSIGN_ERROR );
    }
}


    int
cosign_register( struct connlist *conn, char *cookie, char *ip, char *scookie )
{

    struct reg_param rp;

    if ( !validchars( cookie ) || !validchars( scookie )) {
	return( -1 );
    }

    rp.rp_cookie = cookie;
    rp.rp_ip = ip;
    rp.rp_scookie = scookie;

    if ( cosign_choose_conn( conn, &rp, net_register ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    static int
net_register( SNET *sn, void *vrp )
{
    char		*line;
    struct timeval	 tv;
    struct reg_param	*rp = vrp;

    if ( snet_writef( sn, "REGISTER %s %s %s\r\n", rp->rp_cookie, rp->rp_ip,
	    rp->rp_scookie ) < 0 ) {
	fprintf( stderr, "cosign_register: register failed\n" );
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_register: %s\n", strerror( errno ));
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	return( COSIGN_OK );

    case '4':
        fprintf( stderr, "net_register: %s\n", line);
        return( COSIGN_LOGGED_OUT );

    case '5':
        /* choose another connection */
        return( COSIGN_RETRY );

    default:
        fprintf( stderr, "net_register: %s\n", line );
        return( COSIGN_ERROR );
    }
}

    int
cosign_check( struct connlist *conn, char *cookie, struct userinfo *ui )
{
    static struct check_param cp;

    if ( !validchars( cookie )) {
	return( -1 );
    }

    cp.cp_cookie = cookie;
    cp.cp_ui = ui;

    if ( cosign_choose_conn( conn, &cp, net_check ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    static int
net_check( SNET *sn, void *vcp )
{
    int                 ac, i;
    char		*line;
    char                **av;
    struct timeval	tv;
    struct check_param *cp = vcp;

    if ( snet_writef( sn, "CHECK %s\r\n", cp->cp_cookie ) < 0 ) {
	fprintf( stderr, "cosign_check: check failed\n" );
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_check: %s\n", strerror( errno ));
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	if (( ac = argcargv( line, &av )) < 4 ) {
	    fprintf( stderr, "net_check: wrong num of args: %s\n", line);
	    return( COSIGN_ERROR );
	}
	if ( strlen( av[ 2 ] ) >= sizeof( cp->cp_ui->ui_login )) {
	    fprintf( stderr, "net_check: username %s too long", av[ 2 ] );
	    return( COSIGN_ERROR );
	}
	strcpy( cp->cp_ui->ui_login, av[ 2 ] );

	if ( cosign_protocol == 0 ) {
	    cp->cp_ui->ui_factors[ 0 ] = NULL;
	    return( COSIGN_OK );
	}

	/* protocol v2 */
	if ( strlen( av[ 1 ] ) >= sizeof( cp->cp_ui->ui_ipaddr )) {
	    fprintf( stderr, "net_check: ip address %s too long", av[ 1 ] );
	    return( COSIGN_ERROR );
	}
	strcpy( cp->cp_ui->ui_ipaddr, av[ 1 ] );

	if ( ac - 3 > COSIGN_MAXFACTORS - 1 ) {
	    fprintf( stderr, "net_check: too many factors (%d)", ac - 3 );
            return( COSIGN_ERROR );
	}
	for ( i = 3; i < ac; i++ ) {
	    cp->cp_ui->ui_factors[ i - 3 ] = strdup( av[ i ] );
	}
	cp->cp_ui->ui_factors[ i - 3 ] = NULL;
	return( COSIGN_OK );

    case '4':
        fprintf( stderr, "net_check: %s\n", line);
        return( COSIGN_LOGGED_OUT );

    case '5':
        /* choose another connection */
        return( COSIGN_RETRY );

    default:
        fprintf( stderr, "net_check: %s\n", line );
        return( COSIGN_ERROR );
    }
}

    int
connect_sn( struct connlist *conn )
{
    int			s, ac, err = -1, zero = 0;
    char		*line, **av, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;
    struct protoent	*proto;

    if (( s = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
	perror( "socket" );
	return( -1 );
    }

    if (( proto = getprotobyname( "tcp" )) != NULL ) {
	if ( setsockopt( s, proto->p_proto, TCP_NODELAY,
		&zero, sizeof( zero )) < 0 ) {
	    perror( "setsockopt" );
	}
    }

    if ( connect( s, ( struct sockaddr *)&conn->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	fprintf( stderr, "connect %s:%d: %s\n",
		inet_ntoa(conn->conn_sin.sin_addr),
		ntohs( conn->conn_sin.sin_port ), strerror( errno ));
	(void)close( s );
	return( -1 );
    }

    if (( conn->conn_sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	fprintf( stderr, "connect_sn: snet_attach failed\n" );
	(void)close( s );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connect_sn: snet_getline_multi failed\n" );
	goto done;
    }
    if ( *line != '2' ) {
	fprintf( stderr, "connect_sn: %s", line );
	goto done;
    }
    if (( ac = argcargv( line, &av )) < 4 ) {
        fprintf( stderr, "connect_sn: argcargv: %s", line );
        goto done;
    }
    if (( cosign_protocol = strtol( av[ 1 ], (char **)NULL, 10 )) != 2 ) {
        fprintf( stderr, "connect_sn: falling back to v0\n" );
        cosign_protocol = 0;
    } else {
        cosign_protocol = 2 ;
    }

    if ( cosign_protocol == 2 ) {
        if ( snet_writef( conn->conn_sn, "STARTTLS 2\r\n" ) < 0 ) {
            fprintf( stderr, "connect_sn: starttls 2 failed" );
            goto done;
        }
    } else {
        if ( snet_writef( conn->conn_sn, "STARTTLS\r\n" ) < 0 ) {
            fprintf( stderr, "connect_sn: starttls failed" );
            goto done;
        }
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connect_sn: snet_getline_multi failed\n" );
	goto done;
    }
    if ( *line != '2' ) {
	fprintf( stderr, "connect_sn: %s\n", line );
	goto done;
    }

    if ( snet_starttls( conn->conn_sn, ctx, 0 ) != 1 ) {
	fprintf( stderr, "snet_starttls: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	err = -2;
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( conn->conn_sn->sn_ssl )) == NULL ) {
	fprintf( stderr, "no certificate\n" );
	err = -2;
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));
    /* cn and host must match */
    X509_free( peer );
    if ( strcasecmp( buf, cosign_host ) != 0 ) {
	fprintf( stderr, "cn=%s & host=%s don't match!\n", buf, cosign_host );
	X509_free( peer );
	err = -2;
	goto done;
    }

    if ( cosign_protocol == 2 ) {
        tv = timeout;
        if (( line = snet_getline_multi( conn->conn_sn, logger, &tv ))
		== NULL ) {
            fprintf( stderr, "connect_sn: snet_getline_multi failed" );
            goto done;
        }
        if ( *line != '2' ) {
            fprintf( stderr, "connect_sn: starttls 2: %s", line );
            goto done;
        }
    }
    return( 0 );

done:
    if ( snet_close( conn->conn_sn ) != 0 ) {
	fprintf( stderr, "connect_sn: snet_close failed\n" );
    }
    conn->conn_sn = NULL;

    return( err );
}


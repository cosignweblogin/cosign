/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#define OPENSSL_DISABLE_OLD_DES_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "cosigncgi.h"
#include "network.h"

static void (*logger)( char * ) = NULL;
static struct timeval		timeout = { 10 * 60, 0 };
extern int	errno;
SSL_CTX		*ctx;
extern char	*cosign_host;

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
connlist_setup( char *host, int port )
{

    int			i;
    struct hostent	*he;
    struct connlist	*head, *new, **tail;

    if (( he = gethostbyname( host )) == NULL ) {
        fprintf( stderr, "%s no wanna give hostnames\n", host );
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

    void
ssl_setup( void )
{

    char	*certfile = _COSIGN_TLS_CERT;
    char	*cryptofile = _COSIGN_TLS_KEY;
    char	*cadir = _COSIGN_TLS_CADIR;

    if ( access( cryptofile, R_OK ) != 0 ) {
        perror( cryptofile );
        exit( 1 );
    }

    if ( access( certfile, R_OK ) != 0 ) {
        perror( certfile );
        exit( 1 );
    }

    if ( access( cadir, R_OK ) != 0 ) {
        perror( cadir );
        exit( 1 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if (( ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	fprintf( stderr, "SSL_CTX_new: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }

    if ( SSL_CTX_use_PrivateKey_file( ctx, cryptofile, SSL_FILETYPE_PEM )
	    != 1 ) {
	fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	exit( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( ctx, certfile ) != 1) {
	fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	exit( 1 );
    }
    if ( SSL_CTX_check_private_key( ctx ) != 1 ) {
	fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }

    if ( SSL_CTX_load_verify_locations( ctx, NULL, cadir ) != 1 ) {
	fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	exit( 1 );
    }
    SSL_CTX_set_verify( ctx,
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return;
}

    int
cosign_choose_conn( struct connlist *head, void *netparams,
	int (*fp)( SNET *, void * ))
{

    struct connlist 	*cur;
    int 		rc, ret = 0;

    for ( cur = head; cur != NULL; cur = cur->conn_next ) {
        if ( cur->conn_sn == NULL ) {
            continue;
        }
        if (( rc = (*fp)( cur->conn_sn, netparams )) < 0 ) {
            if ( snet_close( cur->conn_sn ) != 0 ) {
                fprintf( stderr, "choose_conn: snet_close failed\n" );
            }
            cur->conn_sn = NULL;
        }

        if ( rc > 0 ) {
            goto done;
        }
    }

    /* all are closed or we didn't like their answer */
    for ( cur = head; cur != NULL; cur = cur->conn_next ) {
        if ( cur->conn_sn != NULL ) {
            continue;
        }
        if (( ret = connect_sn( cur )) != 0 ) {
            continue;
        }
        if (( rc = (*fp)( cur->conn_sn, netparams )) < 0 ) {
            if ( snet_close( cur->conn_sn ) != 0 ) {
                fprintf( stderr, "cosign_choose_conn: snet_close failed\n" );
            }
            cur->conn_sn = NULL;
        }

        if ( rc > 0 ) {
            goto done;
        }
    }

    if ( ret < 0 ) {
	fprintf( stderr, "cosign_choose_conn: no connection to servers.\n" );
    }
    return( -1 );

done:
    /* not logged in or some such, whatever it failed */
    if ( rc == 1 ) {
        return( -1 );
    } else {
        return( 0 );
    }
}

    int
cosign_login( struct connlist *conn, char *cookie, char *ip, char *user,
	char *realm, char *krb )
{
    struct login_param lp;

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
    int
net_login( SNET *sn, void *vlp )
{
    int			fd = 0;
    ssize_t             rr, size = 0;
    char		*line;
    unsigned char	buf[ 8192 ];
    struct stat         st;
    struct timeval	tv;
    struct login_param	*lp = vlp;

    /*
     * -1 means big error, dump this connection
     * 0 means that this host is having a replication problem
     * 1 means the user is not logged in
     * 2 means everything's peachy
     */


    /* if we're doing BasicAuth or PAM we might not have a ticket */
    if ( lp->lp_krb == NULL ) {
	if ( snet_writef( sn, "LOGIN %s %s %s %s\r\n", lp->lp_cookie, lp->lp_ip,
		lp->lp_user, lp->lp_realm ) < 0 ) {
	    fprintf( stderr, "cosign_login: LOGIN failed\n" );
	    goto done;
	}
    } else {
	if ( snet_writef( sn, "LOGIN %s %s %s %s kerberos\r\n", lp->lp_cookie,
		lp->lp_ip, lp->lp_user, lp->lp_realm ) < 0 ) {
	    fprintf( stderr, "cosign_login: LOGIN failed\n" );
	    goto done;
	}
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_login: %s\n", strerror( errno ));
	goto done;
    }

    if ( lp->lp_krb == NULL ) {
	/* skip ticket stuff */
	goto finish;
    }

    if ( *line != '3' ) {
	fprintf( stderr, "cosign_login: %s\n", line );
	goto done;
    }

    if (( fd = open( lp->lp_krb, O_RDONLY, 0 )) < 0 ) {
	perror( lp->lp_krb );
	goto done;
    }

    if ( fstat( fd, &st) < 0 ) {
	perror( lp->lp_krb );
	goto done2;
    }

    size = st.st_size;
    if ( snet_writef( sn, "%d\r\n", (int)st.st_size ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", lp->lp_user,
	    strerror( errno ));
        goto done2;
    }

    while (( rr = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = timeout;
        if ( snet_write( sn, buf, (int)rr, &tv ) != rr ) {
            fprintf( stderr, "login %s failed: %s\n", lp->lp_user,
                strerror( errno ));
            goto done2;
        }
        size -= rr;
    }
    if ( rr < 0 ) {
        perror( lp->lp_krb );
        goto done2;
    }

    /* Check number of bytes sent to server */
    if ( size != 0 ) {
        fprintf( stderr,
            "login %s failed: Sent wrong number of bytes to server\n",
            lp->lp_user );
        goto done2;
    }

    /* End transaction with server */
    if ( snet_writef( sn, ".\r\n" ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", lp->lp_user,
            strerror( errno ));
        goto done2;
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
    }

finish:
    if ( *line != '2' ) {
        /* Error from server - transaction aborted */
        fprintf( stderr, "cosign_login:%s\n", line );
	goto done2;
    }

    /* Done with server */
    if ( close( fd ) < 0 ) {
        perror( lp->lp_krb );
        return( -1 );
    }

    return( 2 );

done2:
    close( fd );

done:
    return ( -1 );
}

    int
cosign_logout( struct connlist *conn, char *cookie, char *ip )
{
    struct logout_param lp;

    lp.lp_cookie = cookie;
    lp.lp_ip = ip;

    if ( cosign_choose_conn( conn, &lp, net_logout ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    int
net_logout( SNET *sn, void *vlp )
{
    char		*line;
    struct timeval	 tv;
    struct logout_param	*lp = vlp;

    if ( snet_writef( sn, "LOGOUT %s %s\r\n", lp->lp_cookie, lp->lp_ip ) < 0 ) {
	fprintf( stderr, "cosign_logout: LOGOUT failed\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_logout: %s\n", strerror( errno ));
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_logout: %s\n", line );
	return( -1 );
    }

    return( 2 );
}


    int
cosign_register( struct connlist *conn, char *cookie, char *ip, char *scookie )
{

    struct reg_param rp;

    rp.rp_cookie = cookie;
    rp.rp_ip = ip;
    rp.rp_scookie = scookie;

    if ( cosign_choose_conn( conn, &rp, net_register ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    int
net_register( SNET *sn, void *vrp )
{
    char		*line;
    struct timeval	 tv;
    struct reg_param	*rp = vrp;

    if ( snet_writef( sn, "REGISTER %s %s %s\r\n", rp->rp_cookie, rp->rp_ip,
	    rp->rp_scookie ) < 0 ) {
	fprintf( stderr, "cosign_register: register failed\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_register: %s\n", strerror( errno ));
	return( -1 );
    }

    switch( *line ) {
    case '2':
        break;

    case '4':
        fprintf( stderr, "net_reg: %s\n", line);
        return( 1 );

    case '5':
        /* choose another connection */
        fprintf( stderr, "net_reg failover: %s\n", line );
        return( 0 );

    default:
        fprintf( stderr, "cosignd told me sumthin' wacky: %s\n", line );
        return( -1 );
    }

    return( 2 );
}

    int
cosign_check( struct connlist *conn, char *cookie )
{
    struct check_param cp;

    cp.cp_cookie = cookie;

    if ( cosign_choose_conn( conn, &cp, net_check ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

    int
net_check( SNET *sn, void *vcp )
{
    char		*line;
    struct timeval	tv;
    struct check_param *cp = vcp;

    if ( snet_writef( sn, "CHECK %s\r\n", cp->cp_cookie ) < 0 ) {
	fprintf( stderr, "cosign_check: check failed\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_check: %s\n", strerror( errno ));
	return( -1 );
    }

    switch( *line ) {
    case '2':
        break;

    case '4':
        fprintf( stderr, "net_check: %s\n", line);
        return( 1 );

    case '5':
        /* choose another connection */
        fprintf( stderr, "net_check failover: %s\n", line );
        return( 0 );

    default:
        fprintf( stderr, "cosignd told me sumthin' wacky: %s\n", line );
        return( -1 );
    }

    return( 2 );
}

    int
connect_sn( struct connlist *conn )
{
    int			s, err = -1;
    char		*line, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;

    if (( s = socket( PF_INET, SOCK_STREAM, (int)NULL )) < 0 ) {
	    return( -1 );
    }
    if ( connect( s, ( struct sockaddr *)&conn->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	fprintf( stderr, "connect: %s", strerror( errno ));
	(void)close( s );
	return( -1 );
    }

    if (( conn->conn_sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	fprintf( stderr, "connect_sn: snet_attach failed" );
	(void)close( s );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	fprintf( stderr, "connect_sn: %s", line );
	goto done;
    }
    if ( snet_writef( conn->conn_sn, "STARTTLS\r\n" ) < 0 ) {
	fprintf( stderr, "connect_sn: starttls is kaplooey" );
	goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	fprintf( stderr, "connect_sn: %s", line );
	goto done;
    }

    if ( snet_starttls( conn->conn_sn, ctx, 0 ) != 1 ) {
	fprintf( stderr, "snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	err = -2;
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( conn->conn_sn->sn_ssl )) == NULL ) {
	fprintf( stderr, "no certificate" );
	err = -2;
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));
    /* cn and host must match */
    if ( strcmp( buf, cosign_host ) != 0 ) {
	fprintf( stderr, "cn=%s & host=%s don't match!", buf, cosign_host );
	X509_free( peer );
	err = -2;
	goto done;
    }
    X509_free( peer );
    return( 0 );
done:
    if ( snet_close( conn->conn_sn ) != 0 ) {
	fprintf( stderr, "connect_sn: snet_close failed" );
    }
    conn->conn_sn = NULL;

    return( err );
}

#ifdef notdef
   int 
close_sn( struct connlist *conn )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if (( snet_writef( conn->conn_sn, "QUIT\r\n" )) <  0 ) {
	fprintf( stderr, "close_sn: snet_writef failed" );
	return( -1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( conn->conn_sn, logger, &tv ) ) == NULL ) {
	fprintf( stderr, "close_sn: snet_getline_multi failed" );
	return( -1 );
    }
    if ( *line != '2' ) {
	fprintf( stderr, "close_sn: %s", line  );
    }
    if ( snet_close( conn->conn_sn ) != 0 ) {
	fprintf( stderr, "close_sn: snet_close failed" );
    }
    conn->conn_sn = NULL;

    return( 0 );
}

#endif /* notdef */

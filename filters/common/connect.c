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
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>


#include "sparse.h"
#include "cosign.h"
#include "argcargv.h"
#include "mkcookie.h"

#define IP_SZ		254
#define USER_SZ 	30
#define REALM_SZ 	254
#define TKT_PREFIX	"/ticket"
#define MIN(a,b)        ((a)<(b)?(a):(b))

static int connect_sn( struct connlist *, SSL_CTX *, char * );
static int close_sn( SNET *);
void (*logger)( char * ) = NULL;

struct timeval		timeout = { 10 * 60, 0 };

/*
 * -1 means big error, dump this connection
 * 0 means that this host is having a replication problem
 * 1 means the user is not logged in
 * 2 means everything's peachy
 */
    static int
netcheck_cookie( char *secant, struct sinfo *si, SNET *sn )
{
    int			ac;
    char		*line;
    char		**av;
    struct timeval      tv;
    extern int		errno;

    /* CHECK service-cookie */
    if ( snet_writef( sn, "CHECK %s\r\n", secant ) < 0 ) {
	fprintf( stderr, "netcheck_cookie: snet_writef failed\n");
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "netcheck_cookie: snet_getline_multi: %s\n",
		strerror( errno ));
	return( -1 );
    }

    switch( *line ) {
    case '2':
	fprintf( stderr, "We like 200!\n" );
	break;

    case '4':
	fprintf( stderr, "netcheck_cookie: %s\n", line);
	return( 1 );

    case '5':
	/* choose another connection */
	fprintf( stderr, "choose another connection: %s\n", line );
	return( 0 );

    default:
	fprintf( stderr, "cosignd told me sumthin' wacky: %s\n", line );
	return( -1 );
    }

    if (( ac = argcargv( line, &av )) != 4 ) {
	fprintf( stderr, "netcheck_cookie: wrong number of args: %s\n", line);
	return( -1 );
    }

    /* I guess we check some sizing here :) */
    if ( strlen( av[ 1 ] ) >= IP_SZ ) {
	fprintf( stderr, "netcheck_cookie: IP address too long\n" );
	return( -1 );
    }
    strcpy( si->si_ipaddr, av[ 1 ] );
    if ( strlen( av[ 2 ] ) >= USER_SZ ) {
	fprintf( stderr, "netcheck_cookie: username too long\n" );
	return( -1 );
    }
    strcpy( si->si_user, av[ 2 ] );
    if ( strlen( av[ 3 ] ) >= REALM_SZ ) {
	fprintf( stderr, "netcheck_cookie: realm too long\n" );
	return( -1 );
    }
    strcpy( si->si_realm, av[ 3 ] );

    return( 2 );
}

#ifdef KRB
    static int
netretr_ticket( char *secant, struct sinfo *si, SNET *sn )
{
    char		*line;
    char                tmpkrb[ 16 ], krbpath [ 24 ];
    char		buf[ 8192 ];
    int			fd, returnval = -1;
    size_t              size = 0;
    ssize_t             rr;
    struct timeval      tv;
    extern int		errno;

    /* RETR service-cookie TicketType */
    if ( snet_writef( sn, "RETR %s tgt\r\n", secant ) < 0 ) {
	fprintf( stderr, "netretr_ticket: snet_writef failed\n");
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "netretr_ticket: snet_getline_multi: %s\n",
		strerror( errno ));
	return( -1 );
    }

    switch( *line ) {
    case '2':
	fprintf( stderr, "200 in netretr_ticket!\n" );
	break;

    case '4':
	fprintf( stderr, "netretr_ticket: %s\n", line);
	return( 1 );

    case '5':
	/* choose another connection */
	fprintf( stderr, "choose another connection: %s\n", line );
	return( 0 );

    default:
	fprintf( stderr, "cosignd told me sumthin' wacky: %s\n", line );
	return( -1 );
    }

    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	fprintf( stderr, "mkcookie failed in netretr_ticket().\n" );
	return( -1 );
    }
    sprintf( krbpath, "%s/%s", TKT_PREFIX, tmpkrb );

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
        fprintf( stderr, "netretr_ticket for %s failed\n", secant);
        return( -1 );
    }
    size = atoi( line );

    if (( fd = open( krbpath, O_WRONLY | O_CREAT | O_EXCL, 0400 )) < 0 ) {
        perror( krbpath );
        return( -1 );
    }

    /* Get file from server */
    while ( size > 0 ) {
        tv = timeout;
        if (( rr = snet_read( sn, buf, (int)MIN( sizeof( buf ), size ),
                &tv )) <= 0 ) {
            fprintf( stderr, "retrieve tgt failed: %s\n", strerror( errno ));
            returnval = -1;
            goto error2;
        }
        if ( write( fd, buf, (size_t)rr ) != rr ) {
            perror( krbpath );
            returnval = -1;
            goto error2;
        }
        size -= rr;
    }
    if ( close( fd ) != 0 ) {
        perror( krbpath );
        goto error1;
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
        fprintf( stderr, "retr for %s failed: %s\n", secant,
            strerror( errno ));
        returnval = -1;
        goto error1;
    }
    if ( strcmp( line, "." ) != 0 ) {
        fprintf( stderr, "%s", line );
        returnval = -1;
        goto error1;
    }

    /* copy the path to the ticket file */
    /* 524 and copy the 4 path to krb4tkt :) */
    strcpy( si->si_krb5tkt, krbpath );

    return( 2 );

error2:
    close( fd );
error1:
    unlink( krbpath );
    return( returnval );
}
#endif /* KRB */

    int
teardown_conn( struct connlist *cur )
{

    /* close down all children on exit */
    for ( ; cur != NULL; cur = cur->conn_next ) {
	if ( cur->conn_sn != NULL  ) {
	    if ( close_sn( cur->conn_sn ) != 0 ) {
		fprintf( stderr, "teardown_conn: close_sn failed\n" );
	    }
	}
    }
    return( 0 );
}

    int
check_cookie( char *secant, struct sinfo *si, cosign_host_config *cfg,
	int tkt )
{
    struct connlist	**cur, *tmp;
    int			rc, ret = 0;

    /* use connection, then shuffle if there is a problem
     * what happens if they are all bad?
     */
    for ( cur = &cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn == NULL ) {
	    continue;
	}
	if (( rc = netcheck_cookie( secant, si, (*cur)->conn_sn )) < 0 ) {
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		fprintf( stderr, "choose_conn: snet_close failed\n" );
	    }
	    (*cur)->conn_sn = NULL;
	}
#ifdef KRB
	if ( tkt ) {
	    if (( rc = netretr_ticket( secant, si, (*cur)->conn_sn )) < 0 ) {
		if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		    fprintf( stderr, "choose_conn: snet_close failed\n" );
		}
		(*cur)->conn_sn = NULL;
	    }
	}
#endif /* KRB */

	if ( rc > 0 ) {
	    goto done;
	}
    }

    /* all are closed or we didn't like their answer */
    for ( cur = &cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn != NULL ) {
	    continue;
	}
	if (( ret = connect_sn( *cur, cfg->ctx, cfg->host )) != 0 ) {
	    continue;
	}
	if (( rc = netcheck_cookie( secant, si, (*cur)->conn_sn )) < 0 ) {
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		fprintf( stderr, "choose_conn: snet_close failed\n" );
	    }
	    (*cur)->conn_sn = NULL;
	}

#ifdef KRB
	if ( tkt ) {
	    if (( rc = netretr_ticket( secant, si, (*cur)->conn_sn )) < 0 ) {
		if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		    fprintf( stderr, "choose_conn: snet_close failed\n" );
		}
		(*cur)->conn_sn = NULL;
	    }
	}
#endif /* KRB */

	if ( rc > 0 ) {
	    goto done;
	}
    }

    if ( ret < 0 ) {
	return( 2 );
    }
    return( 1 );


done:
    if ( cur != &cfg->cl ) {
	tmp = *cur;
	*cur = (*cur)->conn_next;
	tmp->conn_next = cfg->cl;
	cfg->cl = tmp;
    }
    if ( rc == 1 ) {
	return( 1 );
    } else {
	return( 0 );
    }
}

    static int
connect_sn( struct connlist *cl, SSL_CTX *ctx, char *host )
{
    int			s;
    char		*line, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;

    if (( s = socket( PF_INET, SOCK_STREAM, (int)NULL )) < 0 ) {
	    return( -1 );
    }

    if ( connect( s, ( struct sockaddr *)&cl->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	perror( "connect" );
	(void)close( s );
	return( -1 );
    }

    if (( cl->conn_sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	fprintf( stderr, "connect_sn: snet_attach failed\n" );
	(void)close( s );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connect_sn: snet_getline_multi failed\n" );
	goto done;
    }
    if ( *line != '2' ) {
	fprintf( stderr, "connect_sn: %s\n", line );
	goto done;
    }
    if ( snet_writef( cl->conn_sn, "STARTTLS\r\n" ) < 0 ) {
	fprintf( stderr, "connect_sn: starttls is kaplooey\n" );
	goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connect_sn: snet_getline_multi failed\n" );
	goto done;
    }
    if ( *line != '2' ) {
	fprintf( stderr, "connect_sn: %s\n", line );
	goto done;
    }

    if ( snet_starttls( cl->conn_sn, ctx, 0 ) != 1 ) {
	fprintf( stderr, "snet_starttls: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( cl->conn_sn->sn_ssl )) == NULL ) {
	fprintf( stderr, "no certificate\n" );
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));

    /* cn and host must match */
    if ( strcmp( buf, host ) != 0 ) {
	fprintf( stderr, "cn=%s & host=%s don't match!\n", buf, host );
	X509_free( peer );
	goto done;
    }

    X509_free( peer );

    return( 0 );
done:
    if ( snet_close( cl->conn_sn ) != 0 ) {
	fprintf( stderr, "connect_sn: snet_close failed\n" );
    }
    return( -1 );
}


    static int
close_sn( SNET *sn )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if (( snet_writef( sn, "QUIT\r\n" )) <  0 ) {
	fprintf( stderr, "close_sn: snet_writef failed\n" );
	return( -1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( sn, logger, &tv ) ) == NULL ) {
	fprintf( stderr, "close_sn: snet_getline_multi failed\n" );
	return( -1 );
    }
    if ( *line != '2' ) {
	fprintf( stderr, "close_sn: %s\n", line  );
    }
    if ( snet_close( sn ) != 0 ) {
	fprintf( stderr, "close_sn: snet_close failed\n" );
	return( -1 );
    }
    return( 0 );
}

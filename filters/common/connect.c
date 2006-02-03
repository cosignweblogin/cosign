/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>

#include <httpd.h>
#include <http_log.h>

#define OPENSSL_DISABLE_OLD_DES_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "argcargv.h"
#include "sparse.h"
#include "cosign.h"
#include "mkcookie.h"
#include "rate.h"
#include "log.h"

#ifndef MIN
#define MIN(a,b)        ((a)<(b)?(a):(b))
#endif 

static int connect_sn( struct connlist *, cosign_host_config *, server_rec * );
static int close_sn( struct connlist *, server_rec * );
static void (*logger)( char * ) = NULL;

static struct timeval		timeout = { 10 * 60, 0 };

int				cosign_protocol = 0;
static struct rate   		checkpass = { 0 };
static struct rate   		checkfail = { 0 };
static struct rate   		checkunknown = { 0 };
static double             	rate;
    static int
netcheck_cookie( char *scookie, struct sinfo *si, struct connlist *conn,
	server_rec *s, cosign_host_config *cfg )
{
    int			i, j, ac, fc = cfg->reqfc;
    char		*p, *line, **av, **fv = cfg->reqfv;
    struct timeval      tv;
    SNET		*sn = conn->conn_sn;
    extern int		errno;

    /* CHECK service-cookie */
    if ( snet_writef( sn, "CHECK %s\r\n", scookie ) < 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: snet_writef failed" );
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	if ( !snet_eof( sn )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: snet_getline_multi: %s",
		strerror( errno ));
	}
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	if (( rate = rate_tick( &checkpass )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: PASS %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
	break;

    case '4':
	if (( rate = rate_tick( &checkfail )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: FAIL %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
	return( COSIGN_LOGGED_OUT );

    case '5':
	/* choose another connection */
	if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: UNKNOWN %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
	return( COSIGN_RETRY );

    default:
	cosign_log( APLOG_ERR, s, "mod_cosign: netcheck_cookie: %s", line );
	return( COSIGN_ERROR );
    }

    if (( ac = argcargv( line, &av )) < 4 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: wrong num of args: %s", line );
	return( COSIGN_ERROR );
    }

    /* I guess we check some sizing here :) */
    if ( strlen( av[ 1 ] ) >= sizeof( si->si_ipaddr )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: IP address too long" );
	return( COSIGN_ERROR );
    }
    strcpy( si->si_ipaddr, av[ 1 ] );
    if ( strlen( av[ 2 ] ) >= sizeof( si->si_user )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: username too long" );
	return( COSIGN_ERROR );
    }
    strcpy( si->si_user, av[ 2 ] );

    if ( cosign_protocol == 2 ) {
	for ( i = 0; i < fc; i++ ) {
	    for ( j = 3; j < ac; j++ ) {
		if ( strcmp( fv[ i ], av[ j ] ) == 0 ) {
		    break;
		}
		    if ( cfg->suffix != NULL ) {
		if (( p = strstr( av[ j ], cfg->suffix )) != NULL ) {
		    if (( strlen( p )) == ( strlen( cfg->suffix ))) {
			*p = '\0';
			if ( strcmp( fv[ i ], av[ j ] ) == 0 ) {
			    *p = *cfg->suffix;
			    break;
			}
		    }
		}
		    }
	    }
	    if ( j >= ac ) {
		/* a required factor wasn't in the check line */
		break;
	    }
	}
	if ( i < fc ) {
	    /* we broke out early */
	    cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: we broke out early" );
	    return( COSIGN_RETRY );
	}

	if ( strlen( av[ 3 ] ) + 1 > sizeof( si->si_factor )) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netcheck: factor %s too long", av[ 3 ] );
	    return( COSIGN_ERROR );
	}
	strcpy( si->si_factor, av[ 3 ] );

	for ( i = 4; i < ac; i++ ) {
	    if ( strlen( av[ i ] ) + 1 + 1 >
		    sizeof( si->si_factor ) - strlen( si->si_factor )) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: netcheck: factor %s too long", av[ i ] );
		return( COSIGN_ERROR );
	    }
	    strcat( si->si_factor, " " );
	    strcat( si->si_factor, av[ i ] );
	}
    }

    if ( strlen( av[ 3 ] ) >= sizeof( si->si_realm )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: realm too long" );
	return( COSIGN_ERROR );
    }
	strcpy( si->si_realm, av[ 3 ] );
#ifdef KRB
    *si->si_krb5tkt = '\0';
#endif /* KRB */
    return( COSIGN_OK );
}

    static int
netretr_proxy( char *scookie, struct sinfo *si, SNET *sn, char *proxydb,
	server_rec *s )
{
    int			fd;
    char		*line;
    char                path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    struct timeval      tv;
    FILE                *tmpfile;

    /* RETR service-cookie cookies */
    if ( snet_writef( sn, "RETR %s cookies\r\n", scookie ) < 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_proxy: snet_writef failed");
	return( COSIGN_ERROR );
    }

    /* name our file and open tmp file */
    if ( snprintf( path, sizeof( path ), "%s/%s", proxydb, scookie ) >=
            sizeof( path )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_proxy: cookie path too long");
        return( COSIGN_ERROR );
    }

    if ( gettimeofday( &tv, NULL ) < 0 ) {
	perror( "gettimeofday" );
	return( COSIGN_ERROR );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i",
	    proxydb, (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_proxy: tmppath too long");
        return( COSIGN_ERROR );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
        perror( tmppath );
        return( COSIGN_ERROR );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
        if ( unlink( tmppath ) != 0 ) {
            perror( tmppath );
        }
        perror( tmppath );
        return( COSIGN_ERROR );
    }

    tv = timeout;
    do {
	if (( line = snet_getline( sn, &tv )) == NULL ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: snet_getline failed" );
	    return ( COSIGN_ERROR );
	}

	switch( *line ) {
	case '2':
	    break;

	case '4':
	    cosign_log( APLOG_ERR, s, "mod_cosign: netretr_proxy: %s", line );
	    return( COSIGN_LOGGED_OUT );

	case '5':
	    /* choose another connection */
	    cosign_log( APLOG_ERR, s, "mod_cosign: netretr_proxy: 5xx" );
	    return( COSIGN_RETRY );

	default:
	    cosign_log( APLOG_ERR, s, "mod_cosign: netretr_proxy: %s", line );
	    return( COSIGN_ERROR );
	}

	if ( strlen( line ) < 3 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: short line: %s", line );
	    return( COSIGN_ERROR );
	}
        if ( !isdigit( (int)line[ 1 ] ) ||
                !isdigit( (int)line[ 2 ] )) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: bad response: %s", line );
	    return( COSIGN_ERROR );
        }

	if ( line[ 3 ] != '\0' &&
		line[ 3 ] != ' ' &&
		line [ 3 ] != '-' ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: bad response: %s", line );
	    return( COSIGN_ERROR );
	}

	if ( line[ 3 ] == '-' ) {
	    fprintf( tmpfile, "x%s\n", &line[ 4 ] );
	}

    } while ( line[ 3 ] == '-' );

    if ( fclose ( tmpfile ) != 0 ) {
        if ( unlink( tmppath ) != 0 ) {
            perror( tmppath );
        }
        perror( tmppath );
        return( COSIGN_ERROR );
    }

    if ( link( tmppath, path ) != 0 ) {
        if ( unlink( tmppath ) != 0 ) {
            perror( tmppath );
        }
        perror( tmppath );
        return( COSIGN_ERROR );
    }

    if ( unlink( tmppath ) != 0 ) {
        perror( tmppath );
    }

    return( COSIGN_OK );
}

#ifdef KRB
    static int
netretr_ticket( char *scookie, struct sinfo *si, SNET *sn, char *tkt_prefix,
	server_rec *s )
{
    char		*line;
    char                tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];
    char		buf[ 8192 ];
    int			fd; 
    size_t              size = 0;
    ssize_t             rr;
    struct timeval      tv;
    extern int		errno;

    /* clear it, in case we can't get it later */
    *si->si_krb5tkt = '\0';

    /* RETR service-cookie TicketType */
    if ( snet_writef( sn, "RETR %s tgt\r\n", scookie ) < 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: snet_writef failed");
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: %s", strerror( errno ));
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	break;

    case '4':
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: %s", line );
	return( COSIGN_LOGGED_OUT );

    case '5':
	/* choose another connection */
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: 5xx" );
	return( COSIGN_RETRY );

    default:
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: %s", line );
	return( COSIGN_ERROR );
    }

    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: mkcookie failed" );
	return( COSIGN_ERROR );
    }

    if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
	    tkt_prefix, tmpkrb ) >= sizeof( krbpath )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krbpath too long" );
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: failed for %s", scookie );
        return( COSIGN_ERROR );
    }
    size = atoi( line );

    if (( fd = open( krbpath, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
        perror( krbpath );
        return( COSIGN_ERROR );
    }

    /* Get file from server */
    while ( size > 0 ) {
        tv = timeout;
        if (( rr = snet_read( sn, buf, (int)MIN( sizeof( buf ), size ),
                &tv )) <= 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: retrieve tgt failed: %s", strerror( errno ));
            goto error2;
        }
        if ( write( fd, buf, (size_t)rr ) != rr ) {
            perror( krbpath );
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
	cosign_log( APLOG_ERR, s, "mod_cosign: retrieve for %s failed: %s",
		scookie, strerror( errno ));
        goto error1;
    }
    if ( strcmp( line, "." ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: %s", line );
        goto error1;
    }

    /* copy the path to the ticket file */
    if ( strlen( krbpath ) >= sizeof( si->si_krb5tkt )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krb5tkt path too long" );
	goto error1;
    }
    strcpy( si->si_krb5tkt, krbpath );

    return( COSIGN_OK );

error2:
    close( fd );
error1:
    unlink( krbpath );
    return( COSIGN_ERROR );
}
#endif /* KRB */

    int
teardown_conn( struct connlist *cur, server_rec *s )
{

    /* close down all children on exit */
    for ( ; cur != NULL; cur = cur->conn_next ) {
	if ( cur->conn_sn != NULL  ) {
	    if ( close_sn( cur, s ) != 0 ) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: teardown_conn: close_sn failed" );
	    }
	}
    }
    return( 0 );
}

    int
cosign_check_cookie( char *scookie, struct sinfo *si, cosign_host_config *cfg,
	int first, server_rec *s )
{
    struct connlist	**cur, *tmp;
    int			rc = COSIGN_ERROR, retry = 0;

    /* use connection, then shuffle if there is a problem
     * what happens if they are all bad?
     */
    for ( cur = &cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn == NULL ) {
	    continue;
	}

	switch ( rc = netcheck_cookie( scookie, si, *cur, s, cfg )) {
	case COSIGN_OK :
	case COSIGN_LOGGED_OUT :
	    goto done;

	case COSIGN_RETRY :
	    retry = 1;
	    break;

	default:
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: cosign_check_cookie: unknown return: %d", rc );
	case COSIGN_ERROR :
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: choose_conn: snet_close failed" );
	    }
	    (*cur)->conn_sn = NULL;
	    break;
	}
    }

    /* all are closed or we didn't like their answer */
    for ( cur = &cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn != NULL ) {
	    continue;
	}
	if (( rc = connect_sn( *cur, cfg, s )) != 0 ) {
	    continue;
	}

	switch ( rc = netcheck_cookie( scookie, si, *cur, s, cfg )) {
	case COSIGN_OK :
	case COSIGN_LOGGED_OUT :
	    goto done;

	case COSIGN_RETRY :
	    retry = 1;
	    break;

	default:
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: cosign_check_cookie: unknown return: %d", rc );
	case COSIGN_ERROR :
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: choose_conn: snet_close failed" );
	    }
	    (*cur)->conn_sn = NULL;
	    break;
	}
    }

    if ( retry ) {
	return( COSIGN_RETRY );
    }
    return( COSIGN_ERROR );

done:
    if ( cur != &cfg->cl ) {
	tmp = *cur;
	*cur = (*cur)->conn_next;
	tmp->conn_next = cfg->cl;
	cfg->cl = tmp;
    }
    if ( rc == COSIGN_LOGGED_OUT ) {
	return( COSIGN_RETRY );
    } else {
	if (( first ) && ( cfg->proxy == 1 )) {
	    if ( netretr_proxy( scookie, si, cfg->cl->conn_sn,
		    cfg->proxydb, s ) != COSIGN_OK ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: choose_conn: " 
			"can't retrieve proxy cookies" );
	    }
	}
#ifdef KRB
	if (( first ) && ( cfg->krbtkt == 1 )) {
	    if ( netretr_ticket( scookie, si, cfg->cl->conn_sn, 
		    cfg->tkt_prefix, s ) != COSIGN_OK ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: choose_conn: " 
			"can't retrieve kerberos ticket" );
	    }
	}
#endif /* KRB */
	return( COSIGN_OK );
    }
}

    static int
connect_sn( struct connlist *cl, cosign_host_config *cfg, server_rec *s )
{
    int			sock, zero = 0, ac = 0;
    char		*line, buf[ 1024 ], **av;
    X509		*peer;
    struct timeval      tv;
    struct protoent	*proto;

    if (( sock = socket( PF_INET, SOCK_STREAM, (int)NULL )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: socket" );
	return( -1 );
    }

    if (( proto = getprotobyname( "tcp" )) != NULL ) {
	if ( setsockopt( sock, proto->p_proto, TCP_NODELAY,
		&zero, sizeof( zero )) < 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: connect_sn: setsockopt: TCP_NODELAY" );
	}
    }

    if ( connect( sock, ( struct sockaddr *)&cl->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: connect" );
	(void)close( sock );
	return( -1 );
    }

    if (( cl->conn_sn = snet_attach( sock, 1024 * 1024 ) ) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: connect_sn: snet_attach failed" );
	(void)close( sock );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: %s", line );
	goto done;
    }

    if (( ac = argcargv( line, &av )) < 4 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: argcargv: %s", line );
	goto done;
    }
    if (( cosign_protocol = strtol( av[ 1 ], (char **)NULL, 10 )) != 2 ) {
	if ( cfg->reqfc > 0  ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: required v2 protocol unsupported by server" );
	    goto done;
	}
	cosign_log( APLOG_ERR, s, "mod_cosign: falling back to v0" );
	cosign_protocol = 0;
    } else {
	cosign_protocol = 2 ;
    }

    if ( cosign_protocol == 2 ) {
	if ( snet_writef( cl->conn_sn, "STARTTLS 2\r\n" ) < 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: connect_sn: starttls 2 failed" );
	    goto done;
	}
    } else {
	if ( snet_writef( cl->conn_sn, "STARTTLS\r\n" ) < 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: connect_sn: starttls failed" );
	    goto done;
	}
    }

    tv = timeout;
    if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: %s", line );
	goto done;
    }

    if ( snet_starttls( cl->conn_sn, cfg->ctx, 0 ) != 1 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( cl->conn_sn->sn_ssl )) == NULL ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: no certificate" );
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));
    X509_free( peer );

    /* cn and host must match */
    if ( strcasecmp( buf, cfg->host ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: cn=%s & host=%s " 
		"don't match!", buf, cfg->host );
	goto done;
    }

    if ( cosign_protocol == 2 ) {
	tv = timeout;
	if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: connect_sn: snet_getline_multi failed" );
	    goto done;
	}
	if ( *line != '2' ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: starttls 2: %s", line );
	    goto done;
	}
    }

    return( 0 );
done:
    if ( snet_close( cl->conn_sn ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: snet_close failed" );
    }
    cl->conn_sn = NULL;

    return( -1 );
}


    static int
close_sn( struct connlist *cl, server_rec *s )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if (( snet_writef( cl->conn_sn, "QUIT\r\n" )) <  0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: close_sn: snet_writef failed" );
	return( -1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( cl->conn_sn, logger, &tv ) ) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: close_sn: snet_getline_multi failed" );
	return( -1 );
    }
    if ( *line != '2' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: close_sn: %s", line );
    }
    if ( snet_close( cl->conn_sn ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: close_sn: snet_close failed" );
    }
    cl->conn_sn = NULL;

    return( 0 );
}

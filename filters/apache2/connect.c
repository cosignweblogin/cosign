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

#ifdef KRB4
#include <kerberosIV/krb.h>
#include <krb5.h>
#include "krb524.h"
#endif /* KRB4 */

#include "sparse.h"
#include "cosign.h"
#include "argcargv.h"
#include "mkcookie.h"
#include "rate.h"
#include "log.h"

#ifndef MIN
#define MIN(a,b)        ((a)<(b)?(a):(b))
#endif 

static int connect_sn( struct connlist *, SSL_CTX *, char *, server_rec *);
static int close_sn( struct connlist *, server_rec * );
static void (*logger)( char * ) = NULL;

static struct timeval		timeout = { 10 * 60, 0 };

static struct rate   		checkpass = { 0 };
static struct rate   		checkfail = { 0 };
static struct rate   		checkunknown = { 0 };
static double             	rate;

/*
 * -1 means big error, dump this connection
 * 0 means that this host is having a replication problem
 * 1 means the user is not logged in
 * 2 means everything's peachy
 */
    static int
netcheck_cookie( char *scookie, struct sinfo *si, struct connlist *conn,
	server_rec *s )
{
    int			ac;
    char		*line;
    char		**av;
    struct timeval      tv;
    SNET		*sn = conn->conn_sn;
    extern int		errno;

    /* CHECK service-cookie */
    if ( snet_writef( sn, "CHECK %s\r\n", scookie ) < 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: snet_writef failed" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	if ( !snet_eof( sn )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: snet_getline_multi: %s",
		strerror( errno ));
	}
	return( -1 );
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
	return( 1 );

    case '5':
	/* choose another connection */
	if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: UNKNOWN %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
	return( 0 );

    default:
	cosign_log( APLOG_ERR, s, "mod_cosign: netcheck_cookie: %s", line );
	return( -1 );
    }

    if (( ac = argcargv( line, &av )) != 4 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: wrong num of args: %s", line );
	return( -1 );
    }

    /* I guess we check some sizing here :) */
    if ( strlen( av[ 1 ] ) >= sizeof( si->si_ipaddr )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: IP address too long" );
	return( -1 );
    }
    strcpy( si->si_ipaddr, av[ 1 ] );
    if ( strlen( av[ 2 ] ) >= sizeof( si->si_user )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: username too long" );
	return( -1 );
    }
    strcpy( si->si_user, av[ 2 ] );
    if ( strlen( av[ 3 ] ) >= sizeof( si->si_realm )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netcheck_cookie: realm too long" );
	return( -1 );
    }
    strcpy( si->si_realm, av[ 3 ] );

#ifdef KRB
    *si->si_krb5tkt = '\0';
#ifdef KRB4
    *si->si_krb4tkt = '\0';
#endif /* KRB4 */

#endif /* KRB */
    return( 2 );
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
	return( -1 );
    }

    /* name our file and open tmp file */
    if ( snprintf( path, sizeof( path ), "%s/%s", proxydb, scookie ) >=
            sizeof( path )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_proxy: cookie path too long");
        return( -1 );
    }

    if ( gettimeofday( &tv, NULL ) < 0 ) {
	perror( "gettimeofday" );
	return( -1 );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i", proxydb,
            tv.tv_sec, tv.tv_usec, (int)getpid()) >= sizeof( tmppath )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_proxy: tmppath too long");
        return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
        perror( tmppath );
        return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
        if ( unlink( tmppath ) != 0 ) {
            perror( tmppath );
        }
        perror( tmppath );
        return( -1 );
    }

    tv = timeout;
    do {
	if (( line = snet_getline( sn, &tv )) == NULL ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: snet_getline failed" );
	    return ( -1 );
	}

	switch( *line ) {
	case '2':
	    break;

	case '4':
	    cosign_log( APLOG_ERR, s, "mod_cosign: netretr_proxy: %s", line );
	    return( 1 );

	case '5':
	    /* choose another connection */
	    cosign_log( APLOG_ERR, s, "mod_cosign: netretr_proxy: 5xx" );
	    return( 0 );

	default:
	    cosign_log( APLOG_ERR, s, "mod_cosign: netretr_proxy: %s", line );
	    return( -1 );
	}

	if ( strlen( line ) < 3 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: short line: %s", line );
	    return( -1 );
	}
        if ( !isdigit( (int)line[ 1 ] ) ||
                !isdigit( (int)line[ 2 ] )) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: bad response: %s", line );
	    return( -1 );
        }

	if ( line[ 3 ] != '\0' &&
		line[ 3 ] != ' ' &&
		line [ 3 ] != '-' ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: netretr_proxy: bad response: %s", line );
	    return( -1 );
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
        return( -1 );
    }

    if ( link( tmppath, path ) != 0 ) {
        if ( unlink( tmppath ) != 0 ) {
            perror( tmppath );
        }
        perror( tmppath );
        return( -1 );
    }

    if ( unlink( tmppath ) != 0 ) {
        perror( tmppath );
    }

    return( 2 );
}

#ifdef KRB
    static int
netretr_ticket( char *scookie, struct sinfo *si, SNET *sn, int convert,
	char *tkt_prefix,  server_rec *s )
{
    char		*line;
    char                tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];
    char		buf[ 8192 ];
    int			fd, returnval = -1;
    size_t              size = 0;
    ssize_t             rr;
    struct timeval      tv;
    extern int		errno;
#ifdef KRB4
    char                krb4path [ MAXPATHLEN ];
    krb5_principal	kclient, kserver;
    krb5_ccache		kccache;
    krb5_creds		increds, *v5creds = NULL;
    krb5_error_code 	kerror;
    krb5_context 	kcontext;
    CREDENTIALS		v4creds;

#endif /* KRB4 */

    /* clear it, in case we can't get it later */
    *si->si_krb5tkt = '\0';

    /* RETR service-cookie TicketType */
    if ( snet_writef( sn, "RETR %s tgt\r\n", scookie ) < 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: snet_writef failed");
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: %s", strerror( errno ));
	return( -1 );
    }

    switch( *line ) {
    case '2':
	break;

    case '4':
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: %s", line );
	return( 1 );

    case '5':
	/* choose another connection */
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: 5xx" );
	return( 0 );

    default:
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: %s", line );
	return( -1 );
    }

    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: mkcookie failed" );
	return( -1 );
    }

    if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
	    tkt_prefix, tmpkrb ) >= sizeof( krbpath )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krbpath too long" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: failed for %s", scookie );
        return( -1 );
    }
    size = atoi( line );

    if (( fd = open( krbpath, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
        perror( krbpath );
        return( -1 );
    }

    /* Get file from server */
    while ( size > 0 ) {
        tv = timeout;
        if (( rr = snet_read( sn, buf, (int)MIN( sizeof( buf ), size ),
                &tv )) <= 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: retrieve tgt failed: %s", strerror( errno ));
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
	cosign_log( APLOG_ERR, s, "mod_cosign: retrieve for %s failed: %s",
		scookie, strerror( errno ));
        returnval = -1;
        goto error1;
    }
    if ( strcmp( line, "." ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: netretr_ticket: %s", line );
        returnval = -1;
        goto error1;
    }

    /* copy the path to the ticket file */
    if ( strlen( krbpath ) >= sizeof( si->si_krb5tkt )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krb5tkt path too long" );
        returnval = -1;
	goto error1;
    }
    strcpy( si->si_krb5tkt, krbpath );

#ifdef KRB4
    /* clear it, in case we can't get it later */
    *si->si_krb4tkt = '\0';

    if ( !convert ) {
	return( 2 );
    }
    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: mkcookie failed" );
        returnval = -1;
	goto error1;
    }

    if ( snprintf( krb4path, sizeof( krb4path ), "%s/%s",
	    tkt_prefix, tmpkrb ) >= sizeof( krb4path )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krb4path too long" );
	return( -1 );
    }
    krb_set_tkt_string( krb4path );

    if (( kerror = krb5_init_context( &kcontext )) != KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb5_init_context: %s", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    krb524_init_ets( kcontext );
    if (( kerror = krb5_cc_resolve( kcontext, krbpath, &kccache )) !=
	    KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb5_cc_resolve: %s", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if (( kerror = krb5_cc_get_principal( kcontext, kccache, &kclient )) !=
	    KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb5_cc_get_princ: %s", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }
    if (( kerror = krb5_build_principal( kcontext, &kserver,
	    krb5_princ_realm( kcontext, kclient)->length,
	    krb5_princ_realm( kcontext, kclient)->data, "krbtgt",
	    krb5_princ_realm( kcontext, kclient)->data, NULL)) != KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb5_build_princ: %s", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    memset((char *) &increds, 0, sizeof(increds));
    increds.client = kclient;
    increds.server = kserver;
    increds.times.endtime = 0;
    increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    if (( kerror = krb5_get_credentials( kcontext, 0, kccache,
	    &increds, &v5creds )) != KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb5_get_credentials: %s", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if (( kerror = krb524_convert_creds_kdc( kcontext, v5creds, &v4creds )) !=
	    KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb524: %s",
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    /* initialize ticket cache */
    if (( kerror = in_tkt( v4creds.pname, v4creds.pinst )) != KSUCCESS ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: in_tkt: %s", (char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if (( kerror = krb_save_credentials( v4creds.service, v4creds.instance,
	    v4creds.realm, v4creds.session, v4creds.lifetime, v4creds.kvno,
	    &(v4creds.ticket_st), v4creds.issue_date )) != KSUCCESS ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: krb_save_cred: %s",
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if ( strlen( krb4path ) >= sizeof( si->si_krb4tkt )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krb4tkt path too long" );
        returnval = -1;
	goto error1;
    }
    strcpy( si->si_krb4tkt, krb4path );

    memset( &v4creds, 0, sizeof( v4creds ));
    if ( v5creds ) {
	krb5_free_creds( kcontext, v5creds );
    }
    increds.client = 0;
    krb5_free_cred_contents( kcontext, &increds );
    krb5_cc_close( kcontext, kccache );
    krb5_free_context( kcontext );

#endif /* KRB4 */

    return( 2 );

error2:
    close( fd );
error1:
    unlink( krbpath );
#ifdef KRB4
    unlink( krb4path );
#endif /* KRB4 */
    return( returnval );
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
    int			rc = -1;

    /* use connection, then shuffle if there is a problem
     * what happens if they are all bad?
     */
    for ( cur = &cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn == NULL ) {
	    continue;
	}
	if (( rc = netcheck_cookie( scookie, si, *cur, s )) < 0 ) {
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: choose_conn: snet_close failed" );
	    }
	    (*cur)->conn_sn = NULL;
	}

	if ( rc > 0 ) {
	    goto done;
	}
    }

    /* all are closed or we didn't like their answer */
    for ( cur = &cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn != NULL ) {
	    continue;
	}
	if (( rc = connect_sn( *cur, cfg->ctx, cfg->host, s )) != 0 ) {
	    continue;
	}
	if (( rc = netcheck_cookie( scookie, si, *cur, s )) < 0 ) {
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: choose_conn: snet_close failed" );
	    }
	    (*cur)->conn_sn = NULL;
	}

	if ( rc > 0 ) {
	    goto done;
	}
    }

    if ( rc < 0 ) {
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
	if (( first ) && ( cfg->proxy )) {
	    if ( netretr_proxy
		    ( scookie, si, cfg->cl->conn_sn, cfg->proxydb, s ) != 2 ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: choose_conn: " 
			"can't retrieve proxy cookies" );
	    }
	}
#ifdef KRB
	if (( first ) && ( cfg->krbtkt )) {
	    if ( netretr_ticket( scookie, si, cfg->cl->conn_sn, cfg->krb524,
		    cfg->tkt_prefix, s ) != 2 ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: choose_conn: " 
			"can't retrieve kerberos ticket" );
	    }
	}
#endif /* KRB */
	return( 0 );
    }
}

    static int
connect_sn( struct connlist *cl, SSL_CTX *ctx, char *host, 
	server_rec *s )
{
    int			sock;
    char		*line, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;

    if (( sock = socket( PF_INET, SOCK_STREAM, (int)NULL )) < 0 ) {
	return( -1 );
    }

    if ( connect( sock, ( struct sockaddr *)&cl->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	perror( "connect" );
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
    if ( snet_writef( cl->conn_sn, "STARTTLS\r\n" ) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: starttls failed" );
	goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: connect_sn: snet_getline_multi failed" );
	goto done;
    } if ( *line != '2' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: %s", line );
	goto done;
    }

    if ( snet_starttls( cl->conn_sn, ctx, 0 ) != 1 ) {
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
    if ( strcasecmp( buf, host ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: connect_sn: cn=%s & host=%s " 
		"don't match!", buf, host );
	goto done;
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

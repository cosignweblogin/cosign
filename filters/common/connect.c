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

#define MIN(a,b)        ((a)<(b)?(a):(b))

static int connect_sn( struct connlist *, SSL_CTX *, char * );
static int close_sn( struct connlist *);
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
netcheck_cookie( char *scookie, struct sinfo *si, struct connlist *conn )
{
    int			ac;
    char		*line;
    char		**av;
    struct timeval      tv;
    SNET		*sn = conn->conn_sn;
    extern int		errno;

    /* CHECK service-cookie */
    if ( snet_writef( sn, "CHECK %s\r\n", scookie ) < 0 ) {
	fprintf( stderr, "netcheck_cookie: snet_writef failed\n");
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	if ( !snet_eof( sn )) {
	    fprintf( stderr, "netcheck_cookie: snet_getline_multi: %s\n",
		    strerror( errno ));
	}
	return( -1 );
    }

    switch( *line ) {
    case '2':
	if (( rate = rate_tick( &checkpass )) != 0.0 ) {
	    fprintf( stderr, "mod_cosign: STATS CHECK %s: PASS %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
	break;

    case '4':
	if (( rate = rate_tick( &checkfail )) != 0.0 ) {
	    fprintf( stderr, "mod_cosign: STATS CHECK %s: FAIL %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
	return( 1 );

    case '5':
	/* choose another connection */
	if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
	    fprintf( stderr, "mod_cosign: STATS CHECK %s: UNKNOWN %.5f / sec",
		    inet_ntoa( conn->conn_sin.sin_addr ), rate );
	}
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
    if ( strlen( av[ 1 ] ) >= sizeof( si->si_ipaddr )) {
	fprintf( stderr, "netcheck_cookie: IP address too long\n" );
	return( -1 );
    }
    strcpy( si->si_ipaddr, av[ 1 ] );
    if ( strlen( av[ 2 ] ) >= sizeof( si->si_user )) {
	fprintf( stderr, "netcheck_cookie: username too long\n" );
	return( -1 );
    }
    strcpy( si->si_user, av[ 2 ] );
    if ( strlen( av[ 3 ] ) >= sizeof( si->si_realm )) {
	fprintf( stderr, "netcheck_cookie: realm too long\n" );
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
netretr_proxy( char *scookie, struct sinfo *si, SNET *sn, char *proxydb )
{
    int			fd;
    char		*line;
    char                path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    struct timeval      tv;
    FILE                *tmpfile;

    /* RETR service-cookie cookies */
    if ( snet_writef( sn, "RETR %s cookies\r\n", scookie ) < 0 ) {
	fprintf( stderr, "netretr_proxy: snet_writef failed\n");
	return( -1 );
    }

    /* name our file and open tmp file */
    if ( snprintf( path, sizeof( path ), "%s/%s", proxydb, scookie ) >=
            sizeof( path )) {
        fprintf( stderr, "netretr_proxy: cookie path too long\n");
        return( -1 );
    }

    if ( gettimeofday( &tv, NULL ) < 0 ) {
	perror( "gettimeofday" );
	return( -1 );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i", proxydb,
            tv.tv_sec, tv.tv_usec, (int)getpid()) >= sizeof( tmppath )) {
        fprintf( stderr, "netretr_proxy: tmppath too long\n" );
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
	    fprintf( stderr, "netretr_proxy: snet_getline failed.\n" );
	    return ( -1 );
	}

	switch( *line ) {
	case '2':
	    break;

	case '4':
	    fprintf( stderr, "netretr_proxy: %s\n", line);
	    return( 1 );

	case '5':
	    /* choose another connection */
	    fprintf( stderr, "choose another connection: %s\n", line );
	    return( 0 );

	default:
	    fprintf( stderr, "cosignd told me sumthin' wacky: %s\n", line );
	    return( -1 );
	}

	if ( strlen( line ) < 3 ) {
	    fprintf( stderr, "netretr_proxy: short line: %s\n", line );
	    return( -1 );
	}
        if ( !isdigit( (int)line[ 1 ] ) ||
                !isdigit( (int)line[ 2 ] )) {
	    fprintf( stderr, "netretr_proxy: bad response: %s\n", line );
	    return( -1 );
        }

	if ( line[ 3 ] != '\0' &&
		line[ 3 ] != ' ' &&
		line [ 3 ] != '-' ) {
	    fprintf( stderr, "netretr_proxy: bad response: %s\n", line );
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
	char *tkt_prefix )
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

    if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
	    tkt_prefix, tmpkrb ) >= sizeof( krbpath )) {
	fprintf( stderr, "krbpath too long in netretr_ticket().\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
        fprintf( stderr, "netretr_ticket for %s failed\n", scookie);
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
        fprintf( stderr, "retr for %s failed: %s\n", scookie,
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
    if ( strlen( krbpath ) >= sizeof( si->si_krb5tkt )) {
	fprintf( stderr, "netcheck_cookie: krb5tkt path too long\n" );
        returnval = -1;
	goto error1;
    }
    strcpy( si->si_krb5tkt, krbpath );

#ifdef KRB4
    if ( !convert ) {
	return( 2 );
    }
    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	fprintf( stderr, "mkcookie failed in netretr_ticket().\n" );
        returnval = -1;
	goto error1;
    }

    if ( snprintf( krb4path, sizeof( krb4path ), "%s/%s",
	    tkt_prefix, tmpkrb ) >= sizeof( krb4path )) {
	fprintf( stderr, "krb4path too long in netretr_ticket().\n" );
	return( -1 );
    }
    krb_set_tkt_string( krb4path );

    if (( kerror = krb5_init_context( &kcontext )) != KSUCCESS ) {
	fprintf( stderr, "krb5_init_context: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    krb524_init_ets( kcontext );
    if (( kerror = krb5_cc_resolve( kcontext, krbpath, &kccache )) !=
	    KSUCCESS ) {
	fprintf( stderr, "krb5_cc_resolve: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if (( kerror = krb5_cc_get_principal( kcontext, kccache, &kclient )) !=
	    KSUCCESS ) {
	fprintf( stderr, "krb5_cc_get_princ: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }
    if (( kerror = krb5_build_principal( kcontext, &kserver,
	    krb5_princ_realm( kcontext, kclient)->length,
	    krb5_princ_realm( kcontext, kclient)->data, "krbtgt",
	    krb5_princ_realm( kcontext, kclient)->data, NULL)) != KSUCCESS ) {
	fprintf( stderr, "krb5_build_princ: %s\n", 
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
	fprintf( stderr, "krb5_get_credentials: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if (( kerror = krb524_convert_creds_kdc( kcontext, v5creds, &v4creds )) !=
	    KSUCCESS ) {
	fprintf( stderr, "krb524: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    /* initialize ticket cache */
    if (( kerror = in_tkt( v4creds.pname, v4creds.pinst )) != KSUCCESS ) {
	fprintf( stderr, "in_tkt: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if (( kerror = krb_save_credentials( v4creds.service, v4creds.instance,
	    v4creds.realm, v4creds.session, v4creds.lifetime, v4creds.kvno,
	    &(v4creds.ticket_st), v4creds.issue_date )) != KSUCCESS ) {
	fprintf( stderr, "krb_save_cred: %s\n", 
		(char *)error_message( kerror ));
        returnval = -1;
	goto error1;
    }

    if ( strlen( krb4path ) >= sizeof( si->si_krb4tkt )) {
	fprintf( stderr, "netcheck_cookie: krb4tkt path too long\n" );
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
teardown_conn( struct connlist *cur )
{

    /* close down all children on exit */
    for ( ; cur != NULL; cur = cur->conn_next ) {
	if ( cur->conn_sn != NULL  ) {
	    if ( close_sn( cur ) != 0 ) {
		fprintf( stderr, "teardown_conn: close_sn failed\n" );
	    }
	}
    }
    return( 0 );
}

    int
cosign_check_cookie( char *scookie, struct sinfo *si, cosign_host_config *cfg,
	int first )
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
	if (( rc = netcheck_cookie( scookie, si, *cur )) < 0 ) {
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		fprintf( stderr, "choose_conn: snet_close failed\n" );
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
	if (( rc = connect_sn( *cur, cfg->ctx, cfg->host )) != 0 ) {
	    continue;
	}
	if (( rc = netcheck_cookie( scookie, si, *cur )) < 0 ) {
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		fprintf( stderr, "choose_conn: snet_close failed\n" );
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
		    ( scookie, si, cfg->cl->conn_sn, cfg->proxydb) != 2 ) {
		fprintf( stderr, "Can't retrieve proxy cookies\n" );
	    }
	}
#ifdef KRB
	if (( first ) && ( cfg->krbtkt )) {
	    if ( netretr_ticket( scookie, si, cfg->cl->conn_sn, cfg->krb524,
		    cfg->tkt_prefix) != 2 ) {
		fprintf( stderr, "Can't retrieve kerberos ticket\n" );
	    }
	}
#endif /* KRB */
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
    if ( strcasecmp( buf, host ) != 0 ) {
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
    cl->conn_sn = NULL;

    return( -1 );
}


    static int
close_sn( struct connlist *cl )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if (( snet_writef( cl->conn_sn, "QUIT\r\n" )) <  0 ) {
	fprintf( stderr, "close_sn: snet_writef failed\n" );
	return( -1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( cl->conn_sn, logger, &tv ) ) == NULL ) {
	fprintf( stderr, "close_sn: snet_getline_multi failed\n" );
	return( -1 );
    }
    if ( *line != '2' ) {
	fprintf( stderr, "close_sn: %s\n", line  );
    }
    if ( snet_close( cl->conn_sn ) != 0 ) {
	fprintf( stderr, "close_sn: snet_close failed\n" );
    }
    cl->conn_sn = NULL;

    return( 0 );
}

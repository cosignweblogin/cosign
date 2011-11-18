/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <regex.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <utime.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "command.h"
#include "conf.h"
#include "cparse.h"
#include "mkcookie.h"
#include "cosignproto.h"
#include "rate.h"
#include "argcargv.h"
#include "wildcard.h"

#ifndef MIN
#define MIN(a,b)        ((a)<(b)?(a):(b))
#endif

extern int			idle_out_time;
extern int			grey_time;
extern int			hashlen;
extern int			strict_checks;
extern struct timeval		cosign_net_timeout;
extern struct sockaddr_in	cosign_sin;
extern char			*cosign_tickets;


static int	f_noop( SNET *, int, char *[], SNET * );
static int	f_quit( SNET *, int, char *[], SNET * );
static int	f_help( SNET *, int, char *[], SNET * );
static int	f_notauth( SNET *, int, char *[], SNET * );
static int	f_login( SNET *, int, char *[], SNET * );
static int	f_logout( SNET *, int, char *[], SNET * );
static int	f_register( SNET *, int, char *[], SNET * );
static int	f_check( SNET *, int, char *[], SNET * );
static int	f_retr( SNET *, int, char *[], SNET * );
static int	f_time( SNET *, int, char *[], SNET * );
static int	f_daemon( SNET *, int, char *[], SNET * );
static int	f_starttls( SNET *, int, char *[], SNET * );

static int	do_register( char *, char *, char * );
static int	retr_ticket( SNET *, struct servicelist *, char * );
static int	retr_proxy( SNET *, char *, SNET * );

struct command {
    char	*c_name;
    int		(*c_func)( SNET *, int, char *[], SNET * );
};

struct command	unauth_commands[] = {
    { "NOOP",		f_noop },
    { "QUIT",		f_quit },
    { "HELP",		f_help },
    { "STARTTLS",	f_starttls },
    { "LOGIN",		f_notauth },
    { "LOGOUT",		f_notauth },
    { "REGISTER",	f_notauth },
    { "CHECK",		f_notauth },
    { "REKEY",		f_notauth },
    { "RETR",		f_notauth },
    { "TIME",		f_notauth },
    { "DAEMON",		f_notauth },
};

struct command	auth_commands[] = {
    { "NOOP",		f_noop },
    { "QUIT",		f_quit },
    { "HELP",		f_help },
    { "STARTTLS",	f_starttls },
    { "LOGIN",		f_login },
    { "LOGOUT",		f_logout },
    { "REGISTER",	f_register },
    { "CHECK",		f_check },
    { "REKEY",		f_check },
    { "RETR",		f_retr },
    { "TIME",		f_time },
    { "DAEMON",		f_daemon },
};

extern char	*cosign_version;
extern int	debug;
extern SSL_CTX	*ctx;
struct command 	*commands = unauth_commands;
struct authlist	*al = NULL;
struct rate	checkpass = { 0 };
struct rate	checkfail = { 0 };
struct rate	checkunknown = { 0 };

char		*remote_cn = NULL;
int		replicated = 0; /* we are not talking to ourselves */
int		protocol = COSIGN_PROTO_V0; 
unsigned int	client_capa = 0;
int	ncommands = sizeof( unauth_commands ) / sizeof(unauth_commands[ 0 ] );

    int
f_quit( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    snet_writef( sn, "%d Service closing transmission channel\r\n", 221 );
    exit( 0 );
}

    int
f_noop( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    snet_writef( sn, "%d cosign v%s\r\n", 250, cosign_version );
    return( 0 );
}

    int
f_help( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    snet_writef( sn, "%d Slainte Mhath! http://weblogin.org\r\n", 203 );
    return( 0 );
}

    int
f_notauth( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    snet_writef( sn, "%d You must call STARTTLS first!\r\n", 550 );
    return( 0 );
}

/* banner sent to client on connection & after successful TLS negotiation */
    static void
banner( SNET *sn )
{
    snet_writef( sn, "220 2 Collaborative Web Single Sign-On "
		"[COSIGNv%d FACTORS=%d REKEY]\r\n",
		COSIGN_PROTO_CURRENT, COSIGN_MAXFACTORS );
}

    int
f_starttls( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    int				rc;
    X509			*peer;
    char			buf[ 1024 ];

    /* STARTTLS with no additional parameters is assumed to be protocol 0 */
    if ( ac >= 2 ) {
	errno = 0;
	protocol = strtol( av[ 1 ], (char **)NULL, 10 );
	if ( !COSIGN_PROTO_MIN_REQUIRED( protocol, COSIGN_PROTO_V2) || errno ) {
	    if ( errno ) {
		syslog( LOG_ERR, "f_starttls: protocol: strtol %s: %s",
			av[ 1 ], strerror( errno ));
	    }
	    snet_writef( sn, "%d Protocol version %s unrecognized\r\n",
			 502, av[ 1 ] );

	    protocol = COSIGN_PROTO_V0;

	    return( 1 );
	}
    }

    snet_writef( sn, "%d Ready to start TLS\r\n", 220 );

    /*
     * Begin TLS
     */
    if (( rc = snet_starttls( sn, ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "f_starttls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ) );
	snet_writef( sn, "%d SSL didn't work error!\r\n", 501 );
	return( 1 );
    }
    if (( peer = SSL_get_peer_certificate( sn->sn_ssl ))
	    == NULL ) {
	syslog( LOG_ERR, "no peer certificate" );
	return( -1 );
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ),
		NID_commonName, buf, sizeof( buf ));
    X509_free( peer );
    if (( al = authlist_find( buf )) == NULL ) {
	syslog( LOG_ERR, "f_starttls: No access for %s", buf );
	snet_writef( sn, "%d No access for %s\r\n", 401, buf );
	exit( 1 );
    }

    /* store CN for use with CHECK and RETR */
    if (( remote_cn = strdup( buf )) == NULL ) {
	syslog( LOG_ERR, "f_starttls: strdup %s: %m", buf );
	return( -1 );
    }

    syslog( LOG_INFO, "STARTTLS %s %d %s",
	    inet_ntoa( cosign_sin.sin_addr ), protocol, buf );

    commands = auth_commands;
    ncommands = sizeof( auth_commands ) / sizeof( auth_commands[ 0 ] );
    if ( COSIGN_PROTO_MIN_REQUIRED( protocol, COSIGN_PROTO_V2 )) {
	banner( sn );
    }
    return( 0 );
}


    int
f_login( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    FILE		*tmpfile;
    ACAV		*facav;
    char		tmppath[ MAXCOOKIELEN ], path[ MAXPATHLEN ];
    char		tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];
    char                *sizebuf, *line;
    char                buf[ 8192 ];
    char		**fv;
    int			fd, i, j, fc, already_krb = 0;
    int			krb = 0, err = 1, addinfo = 0, newinfo = 0;
    struct timeval	tv;
    struct cinfo	ci;
    unsigned int        len, rc;
    extern int		errno;

    /*
     * C: LOGIN login_cookie ip principal factor [factor2]
     * S: 200 LOGIN successful: Cookie Stored.
     */

    /*
     * C: LOGIN login_cookie ip principal factor "kerberos"
     * S: 300 LOGIN: Send length then file.
     * C: [length]
     * C: [data]
     * C: .
     */

    if ( al->al_key != CGI ) {
	syslog( LOG_ERR, "%s not allowed to login", al->al_hostname );
	snet_writef( sn, "%d LOGIN: %s not allowed to login.\r\n",
		400, al->al_hostname );
	return( 1 );
    }

    if ( ac < 5 ) {
	syslog( LOG_ERR, "f_login: got %d args, need at least 5", ac );
	snet_writef( sn, "%d LOGIN: Wrong number of args.\r\n", 500 );
	return( 1 );
    }

    if ( ac >= 6 ) {
	if ( strcmp( av[ ac - 1 ], "kerberos" ) == 0 ) {
	    krb = 1;
	    ac--;
	    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
		syslog( LOG_ERR, "f_login: mkcookie error." );
		return( -1 );
	    }
	    if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
		    cosign_tickets, tmpkrb ) >= sizeof( krbpath )) {
		syslog( LOG_ERR, "f_login: krbpath too long." );
		return( -1 );
	    }
	}
    }

    if ( mkcookiepath( NULL, hashlen, av[ 1 ], path, sizeof( path )) < 0 ) {
	syslog( LOG_ERR, "f_login: mkcookiepath error" );
	snet_writef( sn, "%d LOGIN: Invalid cookie path.\r\n", 501 );
	return( 1 );
    }

    if ( read_cookie( path, &ci ) == 0 ) {
	addinfo = 1;
	if ( ci.ci_state == 0 ) {
	    syslog( LOG_ERR,
		    "f_login: %s already logged out", av[ 1 ] );
	    snet_writef( sn, "%d LOGIN: Already logged out\r\n", 505 );
	    return( 1 );
	}
	if ( strcmp( av[ 3 ], ci.ci_user ) != 0 ) {
	    syslog( LOG_ERR, "%s in cookie %s does not match %s",
		    ci.ci_user, av[ 1 ], av[ 3 ] );
	    snet_writef( sn,
		"%d user name given does not match cookie\r\n", 402 );
	    return( 1 );
	}
    }

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "f_login: gettimeofday: %m" );
	return( -1 );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%x%x.%i",
	    (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	syslog( LOG_ERR, "f_login: tmppath too long" );
	return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "f_login: open: %s: %m", tmppath );
	return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	/* close */
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink: %m" );
	}
	syslog( LOG_ERR, "f_login: fdopen: %m" );
	return( -1 );
    }

    fprintf( tmpfile, "v2\n" );
    fprintf( tmpfile, "s1\n" );	 /* 1 is logged in, 0 is logged out */

    if ( strlen( av[ 2 ] ) >= sizeof( ci.ci_ipaddr )) {
	goto file_err;
    }
    if ( addinfo ) {
	fprintf( tmpfile, "i%s\n", ci.ci_ipaddr );
    } else {
	fprintf( tmpfile, "i%s\n", av[ 2 ] );
    }

    if ( addinfo ) {
	if ( strcmp( ci.ci_ipaddr_cur, av[ 2 ] ) != 0 ) {
	    newinfo = 1;
	}
    }
    if ( strlen( av[ 2 ] ) >= sizeof( ci.ci_ipaddr_cur )) {
	goto file_err;
    }
    fprintf( tmpfile, "j%s\n", av[ 2 ] );

    if ( strlen( av[ 3 ] ) >= sizeof( ci.ci_user )) {
	goto file_err;
    }
    fprintf( tmpfile, "p%s\n", av[ 3 ] );
    if ( strlen( av[ 4 ] ) >= sizeof( ci.ci_realm )) {
	goto file_err;
    }

    if ( addinfo ) {
	if (( facav = acav_alloc()) == NULL ) {
	    syslog( LOG_ERR, "acav_alloc: %m" );
	    goto file_err;
	}
	if (( fc = acav_parse( facav, ci.ci_realm, &fv )) < 0 ) {
	    syslog( LOG_ERR, "acav_parse: %m" );
	    goto file_err;
	}
	fprintf( tmpfile, "r%s", fv[ 0 ] );
	for ( i = 1; i < fc; i++ ) {
	    fprintf( tmpfile, " %s", fv[ i ] );
	}
	for ( i = 4; i < ac; i++ ) {
	    for ( j = 0; j < fc; j++ ) {
		if ( strcmp( fv[ j ], av[ i ] ) == 0 ) {
		    break;
		}
	    }
	    if ( j >= fc ) {
		fprintf( tmpfile, " %s", av[ i ] );
		newinfo = 1;
	    }
	}
	if ( newinfo == 0 ) {
	    snet_writef( sn, "%d LOGIN Cookie Already Stored.\r\n", 202 );
	    if ( fclose ( tmpfile ) != 0 ) {
		syslog( LOG_ERR, "f_login: fclose: %m" );
	    }
	    if ( unlink( tmppath ) != 0 ) {
		syslog( LOG_ERR, "f_login: unlink %s: %m", tmppath );
	    }
	    return( 0 );
	}
    } else {
	fprintf( tmpfile, "r%s", av[ 4 ] );
	for ( i = 5; i < ac; i++ ) {
	    fprintf( tmpfile, " %s", av[ i ] );
	}
    }
    fprintf( tmpfile, "\n" );

    if ( addinfo ) {
	fprintf( tmpfile, "t%lu\n", ci.ci_itime);
    } else {
	fprintf( tmpfile, "t%lu\n", tv.tv_sec );
    }

    if ( krb ) {
	if (( addinfo ) && ( *ci.ci_krbtkt != '\0' )) {
	    fprintf( tmpfile, "k%s\n", ci.ci_krbtkt );
	    already_krb = 1;
	} else {
	    fprintf( tmpfile, "k%s\n", krbpath );
	}
    } else if ( *ci.ci_krbtkt != '\0' ) {
	fprintf( tmpfile, "k%s\n", ci.ci_krbtkt );
	already_krb = 1;
    }

    if ( fclose ( tmpfile ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink %s: %m", tmppath );
	}
	syslog( LOG_ERR, "f_login: fclose: %m" );
	return( -1 );
    }

    if ( addinfo ) {
	if ( rename( tmppath, path ) != 0 ) {
	    syslog( LOG_ERR, "f_login: rename %s to %s: %m", tmppath, path );
	    err = -1;
	    goto file_err2;
	}
    } else {
	if ( link( tmppath, path ) != 0 ) {
	    syslog( LOG_ERR, "f_login: link %s to %s: %m", tmppath, path );
	    err = -1;
	    goto file_err2;
	}
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink %s: %m", tmppath );
	}
    }

    if (( !krb ) || ( already_krb )) {
	snet_writef( sn, "%d LOGIN successful: Cookie Stored.\r\n", 200 );
	if (( pushersn != NULL ) && ( !replicated )) {
	    snet_writef( pushersn, "LOGIN %s %s %s %s\r\n",
		    av[ 1 ], av[ 2 ], av[ 3 ], av[ 4 ]);
	}
	if ( !replicated ) {
	    syslog( LOG_INFO, "LOGIN %s %s %s", av[ 3 ], av [ 4 ], av [ 2 ] );
	}
	return( 0 );
    }

    snet_writef( sn, "%d LOGIN: Send length then file.\r\n", 300 );

    if (( fd = open( krbpath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "f_login: open: %s: %m", krbpath );
	return( -1 );
    }

    tv = cosign_net_timeout;
    if (( sizebuf = snet_getline( sn, &tv )) == NULL ) {
        syslog( LOG_ERR, "f_login: snet_getline: %m" );
        return( -1 );
    }

    for ( len = atoi( sizebuf ); len > 0; len -= rc ) {
        tv = cosign_net_timeout;
        if (( rc = snet_read(
                sn, buf, (int)MIN( len, sizeof( buf )), &tv )) <= 0 ) {
            syslog( LOG_ERR, "f_login: snet_read: %m" );
            return( -1 );
        }

        if ( write( fd, buf, rc ) != rc ) {
	    syslog( LOG_ERR, "f_login: write to %s: %m", krbpath );
            snet_writef( sn, "%d %s: %s\r\n", 504, krbpath, strerror( errno ));
            return( 1 );
        }
    }

    if ( close( fd ) < 0 ) {
	syslog( LOG_ERR, "f_login: close %s: %m", krbpath );
        snet_writef( sn, "%d %s: %s\r\n", 504, krbpath, strerror( errno ));
        return( 1 );
    }


    tv = cosign_net_timeout;
    tv.tv_usec = 0;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
        syslog( LOG_ERR, "f_login: snet_getline: %m" );
        return( -1 );
    }

    /* make sure client agrees we're at the end */
    if ( strcmp( line, "." ) != 0 ) {
        snet_writef( sn, "%d Length doesn't match sent data\r\n", 505 );
        (void)unlink( krbpath );

	/* if the krb tkt didn't store, unlink the cookie as well */
	if ( unlink( av[ 1 ] ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink: %m" );
	}

        tv = cosign_net_timeout;
        tv.tv_usec = 0;
        for (;;) {
            if (( line = snet_getline( sn, &tv )) == NULL ) {
                syslog( LOG_ERR, "f_login: snet_getline: %m" );
                exit( 1 );
            }
            if ( strcmp( line, "." ) == 0 ) {
                break;
            }
        }
        exit( 1 );
    }


    snet_writef( sn, "%d LOGIN successful: Cookie & Ticket Stored.\r\n", 201 );
    if (( pushersn != NULL ) && ( !replicated )) {
	snet_writef( pushersn, "LOGIN %s %s %s %s %s\r\n",
		av[ 1 ], av[ 2 ], av[ 3 ], av[ 4 ], av[ 5 ]);
    }
    if ( !replicated ) {
	syslog( LOG_INFO, "LOGIN %s %s %s", av[ 3 ], av [ 4 ], av [ 2 ] );
    }
    return( 0 );

file_err:
    (void)fclose( tmpfile );
    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "f_login: unlink: %m" );
    }
    syslog( LOG_ERR, "f_login: bad file format" );
    snet_writef( sn, "%d LOGIN Syntax Error: Bad File Format\r\n", 504 );
    return( 1 );

file_err2:
    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "f_login: unlink: %m" );
    }
    return( err );
}

    int
f_daemon( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    /* DAEMON hostname */

    char	hostname[ MAXHOSTNAMELEN ];

    if ( al->al_key != CGI ) {
	syslog( LOG_ERR, "%s is not a daemon", al->al_hostname );
	snet_writef( sn, "%d DAEMON: %s not a daemon.\r\n",
		470, al->al_hostname );
	return( 1 );
    }

    if ( ac != 2 ) {
	syslog( LOG_ERR, "f_daemon: expected 2 arguments, got %d", ac );
	snet_writef( sn, "%d Syntax error\r\n", 571 );
	return( 1 );
    }

    if ( gethostname( hostname, sizeof( hostname )) < 0 ) {
	syslog( LOG_ERR, "f_daemon: gethostname: %m" );
	snet_writef( sn, "%d DAEMON error. Sorry!\r\n", 572 );
	return( 1 );
    }

    if ( strcasecmp( hostname, av[ 1 ] ) == 0 ) {
	snet_writef( sn, "%d Schizophrenia!\r\n", 471 );
	return( 1 );
    }
    replicated = 1;

    snet_writef( sn, "%d Daemon flag set\r\n", 271 );
    return( 0 );
}

    int
f_time( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    struct utimbuf	new_time;
    struct stat		st;
    struct timeval	tv;
    int			timestamp, state;
    int			total = 0, fail = 0;
    char		*line, path[ MAXPATHLEN ];

    /* TIME */
    /* 3xx */
    /* login_cookie timestamp state */
    /* . */

    if ( al->al_key != CGI ) {
	syslog( LOG_ERR, "%s not allowed to tell time", al->al_hostname );
	snet_writef( sn, "%d TIME: %s not allowed to propogate time.\r\n",
		460, al->al_hostname );
	return( 1 );
    }

    if ( ac != 1 ) {
	syslog( LOG_ERR, "f_time: expected 1 argument, got %d", ac );
	snet_writef( sn, "%d TIME: Wrong number of args.\r\n", 560 );
	return( 1 );
    }

    snet_writef( sn, "%d TIME: Send timestamps.\r\n", 360 );

    tv = cosign_net_timeout;
    while (( line = snet_getline( sn, &tv )) != NULL ) {
	tv = cosign_net_timeout;
	if (( ac = argcargv( line, &av )) < 0 ) {
	    syslog( LOG_ERR, "argcargv: %m" );
	    break;
	}

	if ( strcmp( line, "." ) == 0 ) {
	    break;
	}

	if ( ac != 3 ) {
	    syslog( LOG_ERR, "f_time: wrong number of args" );
	    continue;
	}

	if ( strncmp( av[ 0 ], "cosign=", 7 ) != 0 ) {
	    syslog( LOG_ERR, "f_time: cookie name malformat" );
	    continue;
	}

	if ( mkcookiepath( NULL, hashlen, av[ 0 ], path, sizeof( path )) < 0 ) {
	    syslog( LOG_ERR, "f_time: path name malformat" );
	    continue;
	}

	total++;
	if ( stat( path, &st ) != 0 ) {
	    /* record a missing cookie here */
	    fail++;
	    continue;
	}

	timestamp = atoi( av[ 1 ] ); 
	if ( timestamp > st.st_mtime ) {
	    new_time.modtime = timestamp;
	    utime( path, &new_time );
	}

	state = atoi( av[ 2 ] );
	if (( state == 0 ) && (( st.st_mode & S_ISGID ) != 0 )) {
	    if ( do_logout( path ) < 0 ) {
		syslog( LOG_ERR, "f_time: %s should be logged out!", path );
	    }
	}
    }

    if ( total != 0 ) {
	syslog( LOG_NOTICE, "STATS TIME %s: %d tried, %d%% success",
		al->al_hostname, total, 100 * ( total - fail ) / total );
    }
    snet_writef( sn, "%d TIME successful: we are now up-to-date\r\n", 260 );
    return( 0 );
}

    int
f_logout( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    struct cinfo	ci;
    char		path[ MAXPATHLEN ];

    /* LOGOUT login_cookie ip */

    if ( al->al_key != CGI ) {
	syslog( LOG_ERR, "f_logout: %s not allowed", al->al_hostname );
	snet_writef( sn, "%d LOGOUT: %s not allowed to logout.\r\n",
		410, al->al_hostname );
	return( 1 );
    }

    if ( ac != 3 ) {
	syslog( LOG_ERR, "f_logout: %s wrong number of args", al->al_hostname );
	snet_writef( sn, "%d LOGOUT: Wrong number of args.\r\n", 510 );
	return( 1 );
    }

    if ( mkcookiepath( NULL, hashlen, av[ 1 ], path, sizeof( path )) < 0 ) {
	syslog( LOG_ERR, "f_login: mkcookiepath error" );
	snet_writef( sn, "%d LOGIN: Invalid cookie path.\r\n", 511 );
	return( 1 );
    }

    if ( read_cookie( path, &ci ) != 0 ) {
	snet_writef( sn, "%d LOGOUT error: Sorry\r\n", 513 );
	return( 1 );
    }

    /* double action policy?? */
    if ( ci.ci_state == 0 ) {
	syslog( LOG_ERR, "f_logout: %s already logged out", av[ 1 ] );
	snet_writef( sn, "%d LOGOUT: Already logged out\r\n", 411 );
	return( 1 );
    }

    if ( do_logout( path ) < 0 ) {
	syslog( LOG_ERR, "f_logout: %s: %m", path );
	return( -1 );
    }

    snet_writef( sn, "%d LOGOUT successful: cookie no longer valid\r\n", 210 );
    if (( pushersn != NULL ) && ( !replicated )) {
	snet_writef( pushersn, "LOGOUT %s %s\r\n", av[ 1 ], av [ 2 ] );
    }
    if ( !replicated ) {
	syslog( LOG_INFO, "LOGOUT %s %s %s", ci.ci_user, ci.ci_realm, av[ 2 ] );
    }
    return( 0 );

}

/*
 * associate serivce with login
 * 0 = OK
 * -1 = unknown fatal error
 * 1 = already registered
 */
    int
do_register( char *login, char *login_p, char *scookie_p )
{
    int			fd, rc;
    char		tmppath[ MAXCOOKIELEN ];
    FILE		*tmpfile;
    struct timeval	tv;

    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "do_register: gettimeofday: %m" );
	return( -1 );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%x%x.%i",
	    (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	syslog( LOG_ERR, "do_register: tmppath too long" );
	return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "do_register: open: %s: %m", tmppath );
	return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "do_register: fdopen: %m" );
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "do_register: unlink: %m" );
	}
	return( -1 );
    }

    /* the service cookie file contains the login cookie only */
    fprintf( tmpfile, "l%s\n", login );

    if ( fclose( tmpfile ) != 0 ) {
	syslog( LOG_ERR, "do_register: fclose: %m" );
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "do_register: unlink: %m" );
	}
	return( -1 );
    }

    if ( link( tmppath, scookie_p ) != 0 ) {
	if ( errno == EEXIST ) {
	    rc = 1;
	} else {
	    syslog( LOG_ERR, "do_register: link: %m" );
	    rc = -1;
	}
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "do_register: unlink: %m" );
	}
	return( rc );
    }

    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "do_register: unlink: %m" );
	return( -1 );
    }

    utime( login_p, NULL );

    return( 0 );
}

    int
f_register( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    struct cinfo	ci;
    struct timeval	tv;
    int			rc;
    char		lpath[ MAXPATHLEN ], spath[ MAXPATHLEN ];

    /* REGISTER login_cookie ip service_cookie */

    if ( al->al_key != CGI ) {
	syslog( LOG_ERR, "f_register: %s not allowed", al->al_hostname );
	snet_writef( sn, "%d REGISTER: %s not allowed to register.\r\n",
		420, al->al_hostname );
	return( 1 );
    }

    if ( ac != 4 ) {
	syslog( LOG_ERR, "f_register: %s wrong number of args.",
		al->al_hostname );
	snet_writef( sn, "%d REGISTER: Wrong number of args.\r\n", 520 );
	return( 1 );
    }

    if ( mkcookiepath( NULL, hashlen, av[ 1 ], lpath, sizeof( lpath )) < 0 ) {
	syslog( LOG_ERR, "f_register: mkcookiepath login cookie error" );
	snet_writef( sn, "%d REGISTER: Invalid cookie path.\r\n", 521 );
	return( 1 );
    }

    if ( mkcookiepath( NULL, hashlen, av[ 3 ], spath, sizeof( spath )) < 0 ) {
	syslog( LOG_ERR, "f_register: mkcookiepath service cookie error" );
	snet_writef( sn, "%d REGISTER: Invalid cookie path.\r\n", 522 );
	return( 1 );
    }

    if ( read_cookie( lpath, &ci ) != 0 ) {
	snet_writef( sn, "%d REGISTER error: Sorry\r\n", 523 );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	syslog( LOG_ERR,
		"f_register: %s logged out, can't register", ci.ci_user );
	snet_writef( sn, "%d REGISTER: Already logged out\r\n", 421 );
	return( 1 );
    }

    /* check for idle timeout, and if so, log'em out */
    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_register: gettimeofday: %m" );
	return( -1 );
    }

    if ( tv.tv_sec - ci.ci_itime >= idle_out_time ) {
	if ( tv.tv_sec - ci.ci_itime < ( idle_out_time + grey_time )) {
	    syslog( LOG_NOTICE, "f_register: idle grey window" );
	    snet_writef( sn, "%d REGISTER: Idle Grey Window\r\n", 521 );
	    return( 1 );
	}
	snet_writef( sn, "%d REGISTER: Idle logged out\r\n", 422 );
	if ( do_logout( lpath ) < 0 ) {
	    syslog( LOG_ERR, "f_register: %s: %m", lpath );
	    return( -1 );
	}
	return( 1 );
    }

    if (( rc = do_register( av[ 1 ], lpath, spath )) < 0 ) {
	return( -1 );
    }

    /* double action policy?? */
    if ( rc > 0 ) {
	snet_writef( sn,
		"%d REGISTER error: Cookie already exists\r\n", 226 );
	return( rc );
    }

    snet_writef( sn, "%d REGISTER successful: Cookie Stored.\r\n", 220 );
    if (( pushersn != NULL ) && ( !replicated )) {
	snet_writef( pushersn, "REGISTER %s %s %s\r\n",
		av[ 1 ], av[ 2 ], av [ 3 ] );
    }
    if ( !replicated ) {
	/* just log service name, no need for full cookie */
	(void)strtok( av[ 3 ], "=" );
	syslog( LOG_INFO, "REGISTER %s %s %s %s", 
		ci.ci_user, ci.ci_realm, ci.ci_ipaddr, av[ 3 ] );
    }
    return( 0 );
}

    static struct servicelist *
service_valid( char *service )
{
    struct servicelist	*sl;
    regex_t		preg;
    regmatch_t		svm[ 2 ];
    char		buf[ 1024 ];
    char		*p;
    int			rc;

    /* limit access to CNs with matching cookies */
    if (( p = strchr( service, '=' )) == NULL ) {
	syslog( LOG_ERR, "service_valid: %s missing \"=\"", service );
	return( NULL );
    }
    *p = '\0';

    if (( sl = service_find( service, svm, 2 )) == NULL ) {
	syslog( LOG_ERR, "service_valid: no matching service for %s", service );
	return( NULL );
    }

    /* XXX cosign3 - save compiled regex in sl->sl_auth? */
    if (( rc = regcomp( &preg, sl->sl_auth->al_hostname, REG_EXTENDED)) != 0 ) {
	regerror( rc, &preg, buf, sizeof( buf ));
	syslog( LOG_ERR, "service_valid: regcomp %s: %s",
		sl->sl_auth->al_hostname, buf );
	return( NULL );
    }
    if (( rc = regexec( &preg, remote_cn, 2, svm, 0 )) != 0 ) {
	if ( rc == REG_NOMATCH ) {
	    syslog( LOG_ERR, "service_valid: CN %s not allowed "
			"access to cookie %s (no match)", remote_cn, service );
	} else {
	    regerror( rc, &preg, buf, sizeof( buf ));
	    syslog( LOG_ERR, "service_valid: regexec: %s\n", buf );
	}

	sl = NULL;
	goto service_valid_done;
    }

    /* only match whole CNs */
    if ( svm[ 0 ].rm_so != 0 || svm[ 0 ].rm_eo != strlen( remote_cn )) {
	syslog( LOG_ERR, "service_valid: CN %s not allowed "
			 "access to cookie %s (partial match)",
			 remote_cn, service );
	sl = NULL;
	goto service_valid_done;
    }

    /*
     * if there's a custom cookie substitution pattern, use it.
     * otherwise, the service_find call + the regexec above
     * verifies that the CN has access to the cookie.
     */
    if ( sl->sl_cookiesub != NULL ) {
	if ( match_substitute( sl->sl_cookiesub, sizeof( buf ), buf,
		2, svm, remote_cn ) != 0 ) {
	    syslog( LOG_ERR, "service_find: match_substitute failed" );
	    sl = NULL;
	    goto service_valid_done;
	}

	if ( strcmp( service, buf ) != 0 ) {
	    syslog( LOG_ERR, "service_valid: CN %s not allowed access "
			"to cookie %s (%s != %s)\n", remote_cn, service,
			service, buf );
	    sl = NULL;
	}
    }

    *p = '=';

service_valid_done:
    regfree( &preg );
    return( sl );
}

    int
f_check( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    struct cinfo 	ci;
    struct timeval	tv;
    char		login[ MAXCOOKIELEN ], path[ MAXPATHLEN ];
    char		rekeybuf[ 128 ], rcookie[ 256 ], scpath[ MAXPATHLEN ];
    char		*p;
    int			status;
    double		rate;

    /*
     * C: CHECK servicecookie
     * S: 231 ip principal realm
     */

    /*
     * C: CHECK logincookie
     * S: 232 ip principal realm
     */

    /*
     * C: REKEY servicecookie
     * S: 233 ip principal realm rekeyed-cookie
     */

    if (( al->al_key != CGI ) && ( al->al_key != SERVICE )) {
	syslog( LOG_ERR, "f_check: %s not allowed", al->al_hostname );
	snet_writef( sn, "%d %s: %s not allowed to check.\r\n",
		430, av[ 0 ], al->al_hostname );
	return( 1 );
    }

    if ( ac < 2 || ac > 3 ) {
	syslog( LOG_ERR, "f_check: %s: wrong number of args. "
		"Expected 2 or 3, got %d", al->al_hostname, ac );
	snet_writef( sn, "%d %s: Wrong number of args.\r\n", 530, av[ 0 ] );
	return( 1 );
    }

    if ( mkcookiepath( NULL, hashlen, av[ 1 ], path, sizeof( path )) < 0 ) {
	syslog( LOG_ERR, "f_check: mkcookiepath error" );
	snet_writef( sn, "%d %s: Invalid cookie name.\r\n", 531, av[ 0 ] );
	return( 1 );
    }

    if ( strncmp( av[ 1 ], "cosign-", 7 ) == 0 ) {
	if ( strict_checks && service_valid( av[ 1 ] ) == NULL ) {
	    snet_writef( sn, "%d %s: Invalid cookie\r\n", 534, av[ 0 ] );
	    return( 1 );
	}

	status = 231;
	if ( service_to_login( path, login ) != 0 ) {
	    if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
		syslog( LOG_NOTICE, "STATS CHECK %s: UNKNOWN %.5f / sec",
			inet_ntoa( cosign_sin.sin_addr), rate );
	    }
	    snet_writef( sn, "%d %s: cookie not in db!\r\n", 533, av[ 0 ] );
	    return( 1 );
	}
	if ( COSIGN_PROTO_SUPPORTS_REKEY( protocol )) {
	    if ( strcasecmp( av[ 0 ], "REKEY" ) == 0 ) {

		/* save service cookie path for rekeying below. */
		if ( strlen( path ) >= sizeof( scpath )) {
		    syslog( LOG_ERR, "f_check: %s exceeds bounds.", path );
		    snet_writef( sn, "%d %s: Invalid cookie name.\r\n",
				 531, av[ 0 ]);
		    return( 1 );
		}
		strcpy( scpath, path );

		status = 233;
	    }
	}

	if ( mkcookiepath( NULL, hashlen, login, path, sizeof( path )) < 0 ) {
	    syslog( LOG_ERR, "f_check: mkcookiepath error.." );
	    snet_writef( sn, "%d %s: Invalid cookie name.\r\n", 532, av[ 0 ] );
	    return( 1 );
	}
    } else if ( strncmp( av[ 1 ], "cosign=", 7 ) == 0 ) {
	status = 232;
    } else {
	syslog( LOG_ERR, "f_check: unknown cookie prefix." );
	snet_writef( sn, "%d %s: unknown cookie prefix!\r\n", 432, av[ 0 ] );
	return( 1 );
    }

    if ( read_cookie( path, &ci ) != 0 ) {
	if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
	    syslog( LOG_NOTICE, "STATS CHECK %s: UNKNOWN %.5f / sec",
		    inet_ntoa( cosign_sin.sin_addr), rate);
	}
	snet_writef( sn, "%d %s: Who me? Dunno.\r\n", 534, av[ 0 ] );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	if (( rate = rate_tick( &checkfail )) != 0.0 ) {
	    syslog( LOG_NOTICE, "STATS CHECK %s: FAIL %.5f / sec",
		    inet_ntoa( cosign_sin.sin_addr), rate);
	}
	snet_writef( sn, "%d %s: Already logged out\r\n", 430, av[ 0 ] );
	return( 1 );
    }

    /* check for idle timeout, and if so, log'em out */
    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_check: gettimeofday: %m" );
	return( -1 );
    }

    if ( tv.tv_sec - ci.ci_itime >= idle_out_time ) {
	if ( tv.tv_sec - ci.ci_itime < ( idle_out_time + grey_time )) {
	    if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
		syslog( LOG_NOTICE, "STATS CHECK %s: UNKNOWN %.5f / sec",
			inet_ntoa( cosign_sin.sin_addr ), rate );
	    }
	    syslog( LOG_NOTICE, "f_check: idle grey window" );
	    snet_writef( sn, "%d %s: Idle Grey Window\r\n", 531, av[ 0 ] );
	    return( 1 );
	}
	if (( rate = rate_tick( &checkfail )) != 0.0 ) {
	    syslog( LOG_NOTICE, "STATS CHECK %s: FAIL %.5f / sec",
		    inet_ntoa( cosign_sin.sin_addr), rate);
	}
	snet_writef( sn, "%d %s: Idle logged out\r\n", 431, av[ 0 ] );
	if ( do_logout( path ) < 0 ) {
	    syslog( LOG_ERR, "f_check: %s: %m", login );
	    return( -1 );
	}
	return( 1 );
    }

    /* prevent idle out if we are actually using it */
    utime( path, NULL );

    if (( rate = rate_tick( &checkpass )) != 0.0 ) {
	syslog( LOG_NOTICE, "STATS CHECK %s: PASS %.5f / sec",
		inet_ntoa( cosign_sin.sin_addr), rate);
    }

    if ( status == 233 ) {
	/* rekey service cookie. */

	if ( mkcookie( sizeof( rekeybuf ), rekeybuf ) != 0 ) {
	    syslog( LOG_ERR, "f_check: rekey: mkcookie failed" );
	    snet_writef( sn, "%d %s: rekey failed.\r\n", 536, av[ 0 ] );
	    return( 1 );
	}
	if (( p = strchr( av[ 1 ], '=' )) == NULL ) {
	    syslog( LOG_ERR, "f_check: rekey: bad service name \"%s\".", av[1]);
	    snet_writef( sn, "%d %s rekey failed.\r\n", 536, av[ 0 ] );
	    return( 1 );
	}
	*p = '\0';
	if ( snprintf( rcookie, sizeof( rcookie ), "%s=%s", av[ 1 ], rekeybuf )
		>= sizeof( rcookie )) {
	    syslog( LOG_ERR, "f_check: rekey: new cookie too long." );
	    snet_writef( sn, "%d %s rekey failed.\r\n", 536, av[ 0 ] );
	    return( 1 );
	}
	*p = '=';
	if ( mkcookiepath( NULL, hashlen, rcookie, path, sizeof( path )) < 0 ) {
	    syslog( LOG_ERR, "f_check: rekey: mkcookiepath error." );
	    snet_writef( sn, "%d %s: rekey failed.\r\n", 536, av[ 0 ] );
	    return( 1 );
	}
	if ( rename( scpath, path ) != 0 ) {
	    syslog( LOG_ERR, "f_check: rekey: rename %s to %s failed: %s.",
			scpath, path, strerror( errno ));
	    snet_writef( sn, "%d %s: rekey failed.\r\n", 536, av[ 0 ] );
	    return( 1 );
	}
    }

    if ( COSIGN_PROTO_SUPPORTS_FACTORS( protocol )) {
	snet_writef( sn, "%d %s %s %s %s\r\n",
		status, ci.ci_ipaddr_cur, ci.ci_user, ci.ci_realm,
		( status == 233 ? rcookie : "" ));
    } else {
	/* if there is more than one realm, we just give the first */
	if (( p = strtok( ci.ci_realm, " " )) != NULL ) {
	    snet_writef( sn, "%d %s %s %s\r\n",
		    status, ci.ci_ipaddr, ci.ci_user, p );
	} else {
	    snet_writef( sn, "%d %s %s %s\r\n",
		    status, ci.ci_ipaddr, ci.ci_user, ci.ci_realm );
	}

    }
    return( 0 );
}

    int
f_retr( SNET *sn, int ac, char *av[], SNET *pushersn )
{
    struct servicelist	*sl;
    struct cinfo        ci;
    struct timeval      tv;
    char		lpath[ MAXPATHLEN ], spath[ MAXPATHLEN ];
    char		login[ MAXCOOKIELEN ];

    if (( al->al_key != CGI ) && ( al->al_key != SERVICE )) {
	syslog( LOG_ERR, "f_retr: %s not allowed", al->al_hostname );
	snet_writef( sn, "%d RETR: %s not allowed to retrieve.\r\n",
		442, al->al_hostname );
	return( 1 );
    }

    if ( ac != 3 ) {
	syslog( LOG_ERR, "f_retr: %s Wrong number of args.", al->al_hostname );
	snet_writef( sn, "%d RETR: Wrong number of args.\r\n", 540 );
	return( 1 );
    }

    if (( sl = service_valid( av[ 1 ] )) == NULL ) {
	snet_writef( sn, "%d RETR: Invalid cookie\r\n", 545 );
	return( 1 );
    }

    if ( mkcookiepath( NULL, hashlen, av[ 1 ], spath, sizeof( spath )) < 0 ) {
	syslog( LOG_ERR, "f_retr: mkcookiepath error" );
	snet_writef( sn, "%d RETR: Invalid cookie name.\r\n", 541 );
	return( 1 );
    }

    if ( service_to_login( spath, login ) != 0 ) {
	snet_writef( sn, "%d RETR: cookie not in db!\r\n", 543 );
	return( 1 );
    }

    if ( mkcookiepath( NULL, hashlen, login, lpath, sizeof( lpath )) < 0 ) {
	syslog( LOG_ERR, "f_retr: mkcookiepath error" );
	snet_writef( sn, "%d RETR: Invalid cookie name.\r\n", 541 );
	return( 1 );
    }

    if ( read_cookie( lpath, &ci ) != 0 ) {
	snet_writef( sn, "%d RETR: Who me? Dunno.\r\n", 544 );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	snet_writef( sn, "%d RETR: Already logged out\r\n", 440 );
	return( 1 );
    }

    /* check for idle timeout, and if so, log'em out */
    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_retr: gettimeofday: %m" );
	return( -1 );
    }

    if ( tv.tv_sec - ci.ci_itime >= idle_out_time ) {
	if ( tv.tv_sec - ci.ci_itime < ( idle_out_time + grey_time )) {
	    syslog( LOG_ERR, "f_retr: idle grey window" );
	    snet_writef( sn, "%d RETR: Idle Grey Window\r\n", 541 );
	    return( 1 );
	}
	snet_writef( sn, "%d RETR: Idle logged out\r\n", 441 );
	if ( do_logout( lpath ) < 0 ) {
	    syslog( LOG_ERR, "f_retr: %s: %m", login );
	    return( -1 );
	}
	return( 1 );
    }

    if ( strcmp( av[ 2 ], "tgt") == 0 ) {
	return( retr_ticket( sn, sl, ci.ci_krbtkt ));
    } else if ( strcmp( av[ 2 ], "cookies") == 0 ) {
	return( retr_proxy( sn, login, pushersn ));
    }

    syslog( LOG_ERR, "f_retr: no such retrieve type: %s", av[ 1 ] );
    snet_writef( sn, "%d RETR: No such retrieve type.\r\n", 441 );
    return( 1 );
}

    static int
retr_proxy( SNET *sn, char *login, SNET *pushersn )
{
    char		cookiebuf[ 128 ], lpath[ MAXPATHLEN ];
    char		cbuf[ MAXCOOKIELEN ], spath[ MAXPATHLEN ];
    struct proxies	*proxy;
    int			rc;

    /* S: 241-[cookiename] [hostname to use cookie with]
     * S: 241- ... 
     * S: 241 Cookies registered and sent.
     */
    
    if (( al->al_flag & AL_PROXY ) == 0 ) {
	syslog( LOG_ERR, "%s cannot retrieve cookies", al->al_hostname );
	snet_writef( sn, "%d RETR: %s cannot retrieve cookies.\r\n",
		443, al->al_hostname );
	return( 1 );
    }

    for ( proxy = al->al_proxies; proxy != NULL; proxy = proxy->pr_next ) {
	if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
	    syslog( LOG_ERR, "retr_proxy: mkcookie error" );
	    return( -1 );
	}

	if ( snprintf( cbuf, sizeof( cbuf ), "%s=%s",
		proxy->pr_cookie, cookiebuf ) >= sizeof( cbuf )) {
	    syslog( LOG_ERR, "retr_proxy: full cookie too long" );
	    return( -1 );
	}

	if ( mkcookiepath( NULL, hashlen, cbuf, spath, sizeof( spath )) < 0 ) {
	    syslog( LOG_ERR, "retr_proxy: mkcookiepath error" );
	    return( 1 );
	}

	if ( mkcookiepath( NULL, hashlen, login, lpath, sizeof( lpath )) < 0 ) {
	    syslog( LOG_ERR, "retr_proxy: mkcookiepath error" );
	    return( 1 );
	}
	if (( rc = do_register( login, lpath, spath )) < 0 ) {
	    continue;
	}

	if (( pushersn != NULL ) && ( !replicated )) {
	    snet_writef( pushersn, "REGISTER %s - %s\r\n", login, cbuf );
	}
	snet_writef( sn, "%d-%s %s\r\n", 241, cbuf, proxy->pr_hostname );
    }
    snet_writef( sn, "%d Cookies registered and sent\r\n", 241 );

    return( 0 );
}

    static int
retr_ticket( SNET *sn, struct servicelist *sl, char *krbpath )
{
    struct stat		st;
    int			fd;
    ssize_t             readlen;
    char                buf[ 8192 ];
    struct timeval      tv;

    /* S: 240 Retrieving file
     * S: [size]
     * S: [data]
     * S: .
     */

    if (( sl->sl_flag & SL_TICKET ) == 0 ) {
	syslog( LOG_ERR, "%s not allowed to retrieve tkts",
		sl->sl_auth->al_hostname );
	snet_writef( sn, "%d RETR: %s not allowed to retrieve tkts.\r\n",
		441, sl->sl_auth->al_hostname );
	return( 1 );
    }

    if (( fd = open( krbpath, O_RDONLY, 0 )) < 0 ) {
        syslog( LOG_ERR, "open: %s: %m", krbpath );
        snet_writef( sn, "%d Unable to access %s.\r\n", 547, krbpath );
        return( 1 );
    }

    if ( fstat( fd, &st ) < 0 ) {
        syslog( LOG_ERR, "f_retr: fstat: %m" );
        snet_writef( sn, "%d Access Error: %s\r\n", 548, krbpath );
        if ( close( fd ) < 0 ) {
            syslog( LOG_ERR, "close: %m" );
            return( -1 );
        }
        return( 1 );
    }

    snet_writef( sn, "%d Retrieving file\r\n", 240 );
    snet_writef( sn, "%d\r\n", (int)st.st_size );

    while (( readlen = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = cosign_net_timeout;
        if ( snet_write( sn, buf, (int)readlen, &tv ) != readlen ) {
            syslog( LOG_ERR, "snet_write: %m" );
            return( -1 );
        }
    }

    if ( readlen < 0 ) {
        syslog( LOG_ERR, "read: %m" );
	close( fd );
        return( -1 );
    }

    if ( close( fd ) < 0 ) {
        syslog( LOG_ERR, "close: %m" );
        return( -1 );
    }

    snet_writef( sn, ".\r\n" );

    return( 0 );
}


    int
command( int fd, SNET *pushersn )
{
    SNET				*snet;
    int					ac, i, zero = 0;
    char				**av, *line;
    struct timeval			tv;
    extern int				errno;
    double				rate;
    struct protoent			*proto;

    if (( proto = getprotobyname( "tcp" )) != NULL ) {
	if ( setsockopt( fd, proto->p_proto, TCP_NODELAY,
		&zero, sizeof( zero )) < 0 ) {
	    syslog( LOG_ERR, "setsockopt TCP_NODELAY: %m" );
	}
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	exit( 1 );
    }

    /* for debugging, TLS not required but still available. we
     * need to do the authlist look up here b/c it normally happens
     * in the starttls code which we may not even call. All the
     * f_cmds require an "al".
     */

    if ( tlsopt ) {
	commands = auth_commands;
	ncommands = sizeof( auth_commands ) / sizeof( auth_commands[ 0 ] );
	if (( al = authlist_find( "NOTLS" )) == NULL ) {
	    syslog( LOG_ERR, "No debugging access" );
	    snet_writef( snet, "%d No NOTLS access\r\n", 508 );
	    exit( 1 );
	}
    }

    /*
     * because of problems with legacy client protocol checks, we return a
     * list of capabilities on the same line as the banner. a multi-line
     * banner would be more in the SMTP-like vernacular, but the IIS & Java
     * legacy clients don't handle multi-line banner output gracefully.
     * 
     * 220 2 Collaborative Web Single Sign-On [ CAPA1 CAPA2 ... ]\r\n
     */
    banner( snet );

    tv = cosign_net_timeout;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	/* log everything we get to stdout if we're debugging */
	tv = cosign_net_timeout;
	if ( debug ) {
	    printf( "debug: %s\n", line );
	}
	if (( ac = argcargv( line, &av )) < 0 ) {
	    syslog( LOG_ERR, "argcargv: %m" );
	    break;
	}

	if ( ac == 0 ) {
	    snet_writef( snet, "%d Command unrecognized\r\n", 501 );
	    continue;
	}

	for ( i = 0; i < ncommands; i++ ) {
	    if ( strcasecmp( av[ 0 ], commands[ i ].c_name ) == 0 ) {
		break;
	    }
	}
	if ( i >= ncommands ) {
	    snet_writef( snet, "%d Command %s unregcognized\r\n",
		    500, av[ 0 ] );
	    continue;
	}

	if ( (*(commands[ i ].c_func))( snet, ac, av, pushersn ) < 0 ) {
	    break;
	}
    }

    if (( rate = rate_get( &checkpass )) != 0.0 ) {
	syslog( LOG_NOTICE, "STATS CHECK %s: PASS %.5f / sec",
		inet_ntoa( cosign_sin.sin_addr), rate );
    }
    if (( rate = rate_get( &checkfail )) != 0.0 ) {
	syslog( LOG_NOTICE, "STATS CHECK %s: FAIL %.5f / sec",
		inet_ntoa( cosign_sin.sin_addr), rate );
    }
    if (( rate = rate_get( &checkunknown )) != 0.0 ) {
	syslog( LOG_NOTICE, "STATS CHECK %s: UNKNOWN %.5f / sec",
		inet_ntoa( cosign_sin.sin_addr), rate );
    }

    if ( line != NULL ) {
	snet_writef( snet,
		"491 Service not available, closing transmission channel\r\n" );
    } else {
	if ( snet_eof( snet )) {
	    exit( 0 );
	} else if ( errno == ETIMEDOUT ) {
	    exit( 0 );
	} else {
	    syslog( LOG_ERR, "snet_getline: %m" );
	}
    }

    exit( 1 );

}

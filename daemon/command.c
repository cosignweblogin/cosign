/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "command.h"
#include "config.h"
#include "cparse.h"
#include "mkcookie.h"

#define MIN(a,b)        ((a)<(b)?(a):(b))
#define MAX(a,b)        ((a)>(b)?(a):(b))

#define TKT_PREFIX	"/ticket"

#define IP_SZ		 254
#define USER_SZ		 30
#define REALM_SZ	 254
#define IDLE_OUT	 7200

static int	f_noop ___P(( SNET *, int, char *[] ));
static int	f_quit ___P(( SNET *, int, char *[] ));
static int	f_help ___P(( SNET *, int, char *[] ));
static int	f_notauth ___P(( SNET *, int, char *[] ));
static int	f_login ___P(( SNET *, int, char *[] ));
static int	f_logout ___P(( SNET *, int, char *[] ));
static int	f_register ___P(( SNET *, int, char *[] ));
static int	f_check ___P(( SNET *, int, char *[] ));
static int	f_retr ___P(( SNET *, int, char *[] ));
static int	f_starttls ___P(( SNET *, int, char *[] ));

struct command {
    char	*c_name;
    int		(*c_func) ___P(( SNET *, int, char *[] ));
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
    { "RETR",		f_notauth },
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
    { "RETR",		f_retr },
};

extern char	*version;
extern SSL_CTX	*ctx;
struct command 	*commands = unauth_commands;
struct chosts	*ch = NULL;
int	ncommands = sizeof( unauth_commands ) / sizeof(unauth_commands[ 0 ] );

    int
f_quit( sn, ac, av )
    SNET			*sn;
    int				ac;
    char			*av[];
{
    snet_writef( sn, "%d Service closing transmission channel\r\n", 221 );
    exit( 0 );
}

    int
f_noop( sn, ac, av )
    SNET			*sn;
    int				ac;
    char			*av[];
{
    snet_writef( sn, "%d cosign v%s\r\n", 250, version );
    return( 0 );
}

    int
f_help( sn, ac, av )
    SNET        *sn;
    int         ac;
    char        *av[];
{
    snet_writef( sn, "%d Slainte Mhath!\r\n", 203 );
    return( 0 );
}

    int
f_notauth( sn, ac, av )
    SNET        *sn;
    int         ac;
    char        *av[];
{
    snet_writef( sn, "%d You must call STARTTLS first!\r\n", 550 );
    return( 0 );
}

    int
f_starttls( sn, ac, av )
    SNET			*sn;
    int				ac;
    char			*av[];
{

    int				rc;
    X509			*peer;
    char			buf[ 1024 ];

    if ( ac != 1 ) {
	snet_writef( sn, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    snet_writef( sn, "%d Ready to start TLS\r\n", 220 );

    /*
     * Begin TLS
     */
    if (( rc = snet_starttls( sn, ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "f_starttls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ) );
	snet_writef( sn, "%d SSL didn't work error! XXX\r\n", 501 );
	return( 1 );
    }
    if (( peer = SSL_get_peer_certificate( sn->sn_ssl ))
	    == NULL ) {
	syslog( LOG_ERR, "no peer certificate" );
	return( -1 );
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ),
		NID_commonName, buf, sizeof( buf ));
    if (( ch = chosts_find( buf )) == NULL ) {
	syslog( LOG_ERR, "f_starttls: No access for %s", buf );
	X509_free( peer );
	snet_writef( sn, "%d STARTTLS: no access for %s\r\n", 508, buf );
	return( 1 );
    }

    X509_free( peer );

    commands = auth_commands;
    ncommands = sizeof( auth_commands ) / sizeof( auth_commands[ 0 ] );
    return( 0 );
}


    int
f_login( sn, ac, av )
    SNET        *sn;
    int         ac;
    char        *av[];
{
    FILE		*tmpfile;
    char		tmppath[ MAXPATHLEN ];
    char		tmpkrb[ 16 ], krbpath [ 24 ];
    char                *sizebuf, *line;
    char                buf[ 8192 ];
    int			fd, krb = 0;
    struct timeval	tv;
    struct cinfo	ci;
    unsigned int        len, rc;
    extern int		errno;

    /* LOGIN login_cookie ip principal realm [tgt] */

    if ( ch->ch_key != CGI ) {
	syslog( LOG_ERR, "%s not allowed to login", ch->ch_hostname );
	snet_writef( sn, "%d LOGIN: %s not allowed to login.\r\n",
		400, ch->ch_hostname );
	return( 1 );
    }

    if (( ac != 5 ) && ( ac != 6 )) {
	snet_writef( sn, "%d LOGIN: Wrong number of args.\r\n", 500 );
	return( 1 );
    }

    if ( ac == 6 ) {
	if ( strcmp( av[ 5 ], "kerberos" ) == 0 ) {
	    krb = 1;
	    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
		syslog( LOG_ERR, "f_login: mkcookie error." );
		snet_writef( sn, "%d LOGIN: Server Error .\r\n", 506 );
		return( -1 );
	    }
	    sprintf( krbpath, "%s/%s", TKT_PREFIX, tmpkrb );
	} else {
	    snet_writef( sn, "%d LOGIN: Ticket type not supported.\r\n", 507 );
	    return( 1 );
	}
    }

    if ( strchr( av[ 1 ], '/' ) != NULL ) {
	syslog( LOG_ERR, "f_login: cookie name contains '/'" );
	snet_writef( sn, "%d LOGIN: Invalid cookie name.\r\n", 501 );
	return( 1 );
    }

    if ( strlen( av[ 1 ] ) >= MAXPATHLEN ) {
	syslog( LOG_ERR, "f_login: cookie too long" );
	snet_writef( sn, "%d LOGIN: Cookie too long.\r\n", 502 );
	return( 1 );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_login: gettimeofday: %m" );
	snet_writef( sn, "%d LOGIN Error: Sorry!\r\n", 503 );
	return( -1 );
    }

    if ( snprintf( tmppath, MAXPATHLEN, "%x%x.%i",
	    tv.tv_sec, tv.tv_usec, (int)getpid()) >= MAXPATHLEN ) {
	syslog( LOG_ERR, "f_login: tmppath too long" );
	snet_writef( sn, "%d LOGIN Error: Sorry!\r\n", 503 );
	return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "f_login: open: %m" );
	snet_writef( sn, "%d LOGIN Error: Sorry!\r\n", 503 );
	return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	/* close */
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink: %m" );
	}
	syslog( LOG_ERR, "f_login: fdopen: %m" );
	snet_writef( sn, "%d LOGIN Error: Sorry!\r\n", 503 );
	return( -1 );
    }

    fprintf( tmpfile, "v0\n" );
    fprintf( tmpfile, "s1\n" );	 /* 1 is logged in, 0 is logged out */
    if ( strlen( av[ 2 ] ) >= IP_SZ ) {
	goto file_err;
    }
    fprintf( tmpfile, "i%s\n", av[ 2 ] );
    if ( strlen( av[ 3 ] ) >= USER_SZ ) {
	goto file_err;
    }
    fprintf( tmpfile, "p%s\n", av[ 3 ] );
    if ( strlen( av[ 4 ] ) >= REALM_SZ ) {
	goto file_err;
    }
    fprintf( tmpfile, "r%s\n", av[ 4 ] );
    fprintf( tmpfile, "t%lu\n", tv.tv_sec );
    if ( krb ) {
	fprintf( tmpfile, "k%s\n", krbpath );
    }

    if ( fclose ( tmpfile ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink: %m" );
	}
	syslog( LOG_ERR, "f_login: fclose: %m" );
	snet_writef( sn, "%d LOGIN Error: Sorry!\r\n", 503 );
	return( -1 );
    }

    if ( link( tmppath, av[ 1 ] ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink: %m" );
	}
	if ( errno == EEXIST ) {
	    syslog( LOG_ERR, "f_login: file already exists: %s", av[ 1 ]);
	    if ( read_cookie( av[ 1 ], &ci ) != 0 ) {
		syslog( LOG_ERR, "f_login: read_cookie: XXX" );
		snet_writef( sn, "%d LOGIN error: Sorry\r\n", 503 );
		return( 1 );
	    }
	    if ( ci.ci_state == 0 ) {
		syslog( LOG_ERR,
			"f_login: %s already logged out", av[ 1 ] );
		snet_writef( sn, "%d LOGIN: Already logged out\r\n", 505 );
		return( 1 );
	    }
	    if ( strcmp( av[ 2 ], ci.ci_ipaddr ) != 0 ) {
		syslog( LOG_ERR, "%s in cookie %s does not match %s",
			ci.ci_ipaddr, av[ 1 ], av[ 2 ] );
		snet_writef( sn,
			"%d IP address given does not match cookie\r\n", 401 );
		return( 1 );
	    }
	    if ( strcmp( av[ 3 ], ci.ci_user ) != 0 ) {
		syslog( LOG_ERR, "%s in cookie %s does not match %s",
			ci.ci_user, av[ 1 ], av[ 3 ] );
		snet_writef( sn,
			"%d user name given does not match cookie\r\n", 402 );
		return( 1 );
	    }
	    snet_writef( sn,
		    "%d LOGIN: Cookie already exists\r\n", 201 );
	    return( 1 );
	}
	syslog( LOG_ERR, "f_login: link: %m" );
	snet_writef( sn, "%d LOGIN Error: Sorry!\r\n", 503 );
	return( -1 );
    }

    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "f_login: unlink: %m" );
    }

    if ( !krb ) {
	snet_writef( sn, "%d LOGIN successful: Cookie Stored.\r\n", 200 );
	return( 0 );
    }

    snet_writef( sn, "%d LOGIN: Send length then file.\r\n", 300 );

    if (( fd = open( krbpath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "f_login: open: %s: %m", krbpath );
	snet_writef( sn, "%d %s: %s\r\n", 507, krbpath, strerror( errno ));
	return( -1 );
    }

    tv.tv_sec = 60 * 2;
    tv.tv_usec = 0;
    if (( sizebuf = snet_getline( sn, &tv )) == NULL ) {
        syslog( LOG_ERR, "f_login: snet_getline: %m" );
        return( -1 );
    }
    /* Will there be a limit? */
    len = atoi( sizebuf );

    for ( ; len > 0; len -= rc ) {
        tv.tv_sec = 60 * 2;
        tv.tv_usec = 0;
        if (( rc = snet_read(
                sn, buf, (int)MIN( len, sizeof( buf )), &tv )) <= 0 ) {
            syslog( LOG_ERR, "f_login: snet_read: %m" );
            return( -1 );
        }

        if ( write( fd, buf, rc ) != rc ) {
            snet_writef( sn, "%d %s: %s\r\n", 504, krbpath, strerror( errno ));
            return( 1 );
        }
    }

    if ( close( fd ) < 0 ) {
        snet_writef( sn, "%d %s: %s\r\n", 504, krbpath, strerror( errno ));
        return( 1 );
    }


    tv.tv_sec = 60 * 2;
    tv.tv_usec = 0;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
        syslog( LOG_ERR, "f_login: snet_getline: %m" );
        return( -1 );
    }

    /* make sure client agrees we're at the end */
    if ( strcmp( line, "." ) != 0 ) {
        snet_writef( sn, "%d Length doesn't match sent data\r\n", 505 );
        (void)unlink( krbpath );

	if ( unlink( av[ 1 ] ) != 0 ) {
	    syslog( LOG_ERR, "f_login: unlink: %m" );
	}

	/* if the krb tkt didn't store, unlink the cookie as well */

        tv.tv_sec = 60 * 2;
        tv.tv_usec = 0;
        for (;;) {
            if (( line = snet_getline( sn, &tv )) == NULL ) {
                syslog( LOG_ERR, "f_login: snet_getline: %m" );
                return( -1 );
            }
            if ( strcmp( line, "." ) == 0 ) {
                break;
            }
        }
        return( -1 );
    }

    snet_writef( sn, "%d LOGIN successful: Cookie & Ticket Stored.\r\n", 201 );
    return( 0 );

file_err:
    (void)fclose( tmpfile );
    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "f_login: unlink: %m" );
    }
    syslog( LOG_ERR, "f_login: bad file format" );
    snet_writef( sn, "%d LOGIN Syntax Error: Bad File Format\r\n", 504 );
    return( 1 );
}

    int
f_logout( sn, ac, av )
    SNET        *sn;
    int         ac;
    char        *av[];
{
    struct cinfo	ci;

    /*LOGOUT login_cookie ip */

    if ( ch->ch_key != CGI ) {
	syslog( LOG_ERR, "%s not allowed to logout", ch->ch_hostname );
	snet_writef( sn, "%d LOGOUT: %s not allowed to logout.\r\n",
		410, ch->ch_hostname );
	return( 1 );
    }

    if ( ac != 3 ) {
	snet_writef( sn, "%d LOGOUT: Wrong number of args.\r\n", 510 );
	return( 1 );
    }

    if ( strchr( av[ 1 ], '/' ) != NULL ) {
	syslog( LOG_ERR, "f_logout: cookie name contains '/'" );
	snet_writef( sn, "%d LOGOUT: Invalid cookie name.r\n", 511 );
	return( 1 );
    }

    if ( strlen( av[ 1 ] ) >= MAXPATHLEN ) {
	snet_writef( sn, "%d LOGOUT: Cookie too long\r\n", 512 );
	return( 1 );
    }

    if ( read_cookie( av[ 1 ], &ci ) != 0 ) {
	syslog( LOG_ERR, "f_logout: read_cookie: XXX" );
	snet_writef( sn, "%d LOGOUT error: Sorry\r\n", 513 );
	return( 1 );
    }

    if( strcmp( av[ 2 ], ci.ci_ipaddr ) != 0 ) {
	syslog( LOG_INFO, "%s in cookie %s does not match %s",
		ci.ci_ipaddr, av[ 1 ], av[ 2 ] );
	snet_writef( sn,
		"%d IP address given does not match cookie\r\n", 410 );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	syslog( LOG_ERR, "f_logout: %s already logged out", av[ 1 ] );
	snet_writef( sn, "%d LOGOUT: Already logged out\r\n", 411 );
	return( 1 );
    }

    if ( do_logout( av[ 1 ] ) < 0 ) {
	syslog( LOG_ERR, "f_logout: %s: %m" );
	snet_writef( sn, "%d LOGOUT error: Sorry!\r\n", 514 );
	return( -1 );
    }

    snet_writef( sn, "%d LOGOUT successful: cookie no longer valid\r\n", 210 );
    return( 0 );

}

    int
f_register( sn, ac, av )
    SNET			*sn;
    int				ac;
    char			*av[];
{
    struct cinfo	ci;
    struct timeval	tv;
    int			fd;
    char		tmppath[ MAXPATHLEN ];
    FILE		*tmpfile;


    /* REGISTER login_cookie ip service_cookie */

    if ( ch->ch_key != CGI ) {
	syslog( LOG_ERR, "%s not allowed to register", ch->ch_hostname );
	snet_writef( sn, "%d REGISTER: %s not allowed to register.\r\n",
		420, ch->ch_hostname );
	return( 1 );
    }

    if ( ac != 4 ) {
	snet_writef( sn, "%d REGISTER: Wrong number of args.\r\n", 520 );
	return( 1 );
    }

    if ( strchr( av[ 1 ], '/' ) != NULL ) {
	syslog( LOG_ERR, "f_register: cookie name contains '/'" );
	snet_writef( sn, "%d REGISTER: Invalid cookie name.\r\n", 521 );
	return( 1 );
    }

    if ( strlen( av[ 1 ] ) >= MAXPATHLEN ||
	    strlen( av[ 3 ] ) >= MAXPATHLEN ) {
	snet_writef( sn, "%d REGISTER: Cookie too long\r\n", 522 );
	return( 1 );
    }

    if ( read_cookie( av[ 1 ], &ci ) != 0 ) {
	syslog( LOG_ERR, "f_register: read_cookie: XXX" );
	snet_writef( sn, "%d REGISTER error: Sorry\r\n", 523 );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	syslog( LOG_ERR,
		"f_register: %s already logged out, can't register", av[ 1 ] );
	snet_writef( sn, "%d REGISTER: Already logged out\r\n", 420 );
	return( 1 );
    }

    if ( strcmp( av[ 2 ], ci.ci_ipaddr ) != 0 ) {
	syslog( LOG_ERR, "%s in cookie %s does not match %s",
		ci.ci_ipaddr, av[ 1 ], av[ 2 ] );
	snet_writef( sn,
		"%d IP address given does not match cookie\r\n", 525 );
	return( 1 );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_register: gettimeofday: %m" );
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    /* check for idle timeout, and if so, log'em out */
    if ( tv.tv_sec - ci.ci_itime > IDLE_OUT ) {
	syslog( LOG_INFO, "f_register: idle time out!\n" );
	if ( do_logout( av[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "f_register: %s: %m", av[ 1 ] );
	    snet_writef( sn, "%d REGISTER error: Sorry!\r\n", 524 );
	    return( -1 );
	}
	snet_writef( sn, "%d REGISTER: Idle logged out\r\n", 421 );
	return( 1 );
    }

    if ( snprintf( tmppath, MAXPATHLEN, "%x%x.%i",
	    tv.tv_sec, tv.tv_usec, (int)getpid()) >= MAXPATHLEN ) {
	syslog( LOG_ERR, "f_register: tmppath too long" );
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	syslog( LOG_ERR, "f_register: open: %m" );
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_register: unlink: %m" );
	}
	syslog( LOG_ERR, "f_register: fdopen: %m" );
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    /* the service cookie file contains the login cookie only */
    fprintf( tmpfile, "l%s\n", av[ 1 ] );

    if ( fclose ( tmpfile ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_register: unlink: %m" );
	}
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    if ( link( tmppath, av[ 3 ] ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    syslog( LOG_ERR, "f_register: unlink: %m" );
	}
	if( errno == EEXIST ) {
	    syslog( LOG_ERR,
		    "f_register: service cookie already exists: %s", av[ 3 ]);
	    snet_writef( sn,
		    "%d REGISTER error: Cookie already exists\r\n", 526 );
	    return( 1 );
	}
	syslog( LOG_ERR, "f_register: link: %m" );
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    if ( unlink( tmppath ) != 0 ) {
	syslog( LOG_ERR, "f_register: unlink: %m" );
	snet_writef( sn, "%d REGISTER Error: Sorry!\r\n", 524 );
	return( -1 );
    }

    snet_writef( sn, "%d REGISTER successful: Cookie Stored \r\n", 220 );
    return( 0 );
}

    int
f_check( sn, ac, av )
    SNET			*sn;
    int				ac;
    char			*av[];
{
    struct cinfo 	ci;
    struct timeval	tv;
    char		login[ MAXPATHLEN ];
    int			status;

    /* CHECK (service/login)cookie */

    if (( ch->ch_key != CGI ) && ( ch->ch_key != SERVICE )) {
	syslog( LOG_ERR, "%s not allowed to register", ch->ch_hostname );
	snet_writef( sn, "%d REGISTER: %s not allowed to register.\r\n",
		430, ch->ch_hostname );
	return( 1 );
    }

    if ( ac != 2 ) {
	snet_writef( sn, "%d CHECK: Wrong number of args.\r\n", 530 );
	return( 1 );
    }

    if ( strchr( av[ 1 ], '/' ) != NULL ) {
	syslog( LOG_ERR, "f_check: cookie name contains '/'" );
	snet_writef( sn, "%d CHECK: Invalid cookie name.\r\n", 531 );
	return( 1 );
    }

    if ( strlen( av[ 1 ] ) >= MAXPATHLEN ) {
	snet_writef( sn, "%d CHECK: Service Cookie too long\r\n", 532 );
	return( 1 );
    }

    if ( strncmp( av[ 1 ], "cosign-", 7 ) == 0 ) {
	status = 231;
	if ( service_to_login( av[ 1 ], login ) != 0 ) {
	    syslog( LOG_ERR, "f_check: ask someone else about it!"  );
	    snet_writef( sn, "%d CHECK: cookie not in db!\r\n", 533 );
	    return( 1 );
	}
    } else {
	status = 232;
	strcpy( login, av[ 1 ] );
    }

    if ( read_cookie( login, &ci ) != 0 ) {
	syslog( LOG_ERR, "f_check: read_cookie: XXX" );
	snet_writef( sn, "%d CHECK: Who me? Dunno.\r\n", 534 );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	syslog( LOG_ERR,
		"f_check: %s logged out", login );
	snet_writef( sn, "%d CHECK: Already logged out\r\n", 430 );
	return( 1 );
    }


    /* check for idle timeout, and if so, log'em out */
    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_check: gettimeofday: %m" );
	snet_writef( sn, "%d CHECK Error: Sorry!\r\n", 535 );
	return( -1 );
    }

    if ( tv.tv_sec - ci.ci_itime > IDLE_OUT ) {
	syslog( LOG_INFO, "f_check: idle time out!\n" );
	snet_writef( sn, "%d CHECK: Idle logged out\r\n", 431 );
	if ( do_logout( login ) < 0 ) {
	    syslog( LOG_ERR, "f_check: %s: %m", login );
	    snet_writef( sn, "%d CHECK error: Sorry!\r\n", 534 );
	    return( -1 );
	}
	return( 1 );
    }

    snet_writef( sn,
	    "%d %s %s %s\r\n", status, ci.ci_ipaddr, ci.ci_user, ci.ci_realm );
    return( 0 );
}

    int
f_retr( sn, ac, av )
    SNET                        *sn;
    int                         ac;
    char                        *av[];
{
    struct cinfo        ci;
    struct timeval      tv;
    struct stat		st;
    int			fd;
    ssize_t             readlen;
    char                buf[8192];
    char		login[ MAXPATHLEN ];

    /* RETR service-cookie TicketType] */

    /* XXX check if you are allowed to get tickets */

    if ( ac != 3 ) {
	snet_writef( sn, "%d RETR: Wrong number of args.\r\n", 540 );
	return( 1 );
    }

    if ( strchr( av[ 1 ], '/' ) != NULL ) {
	syslog( LOG_ERR, "f_retr: cookie name contains '/'" );
	snet_writef( sn, "%d RETR: Invalid cookie name.\r\n", 541 );
	return( 1 );
    }

    if ( strlen( av[ 1 ] ) >= MAXPATHLEN ) {
	snet_writef( sn, "%d RETR: Service Cookie too long\r\n", 542 );
	return( 1 );
    }

    if ( strcmp( av[ 2 ], "tgt") != 0 ) {
	syslog( LOG_ERR, "f_retr: no such ticket type: %s", av[ 1 ] );
	snet_writef( sn, "%d RETR: No such ticket type.\r\n", 441 );
    }

    if ( service_to_login( av[ 1 ], login ) != 0 ) {
	syslog( LOG_ERR, "f_retr: ask someone else about it!"  );
	snet_writef( sn, "%d RETR: cookie not in db!\r\n", 543 );
	return( 1 );
    }

    if ( read_cookie( login, &ci ) != 0 ) {
	syslog( LOG_ERR, "f_retr: read_cookie: XXX" );
	snet_writef( sn, "%d RETR: Who me? Dunno.\r\n", 544 );
	return( 1 );
    }

    if ( ci.ci_state == 0 ) {
	syslog( LOG_ERR,
		"f_retr: %s logged out", login );
	snet_writef( sn, "%d RETR: Already logged out\r\n", 440 );
	return( 1 );
    }

    /* check for idle timeout, and if so, log'em out */
    if ( gettimeofday( &tv, NULL ) != 0 ){
	syslog( LOG_ERR, "f_retr: gettimeofday: %m" );
	snet_writef( sn, "%d RETR Error: Sorry!\r\n", 545 );
	return( -1 );
    }

    if ( tv.tv_sec - ci.ci_itime > IDLE_OUT ) {
	syslog( LOG_INFO, "f_retr: idle time out!\n" );
	snet_writef( sn, "%d RETR: Idle logged out\r\n", 441 );
	if ( do_logout( login ) < 0 ) {
	    syslog( LOG_ERR, "f_retr: %s: %m", login );
	    snet_writef( sn, "%d RETR error: Sorry!\r\n", 546 );
	    return( -1 );
	}
	return( 1 );
    }

    /* if we get here, we can give them the data pointed to by k */

    if (( fd = open( ci.ci_krbtkt, O_RDONLY, 0 )) < 0 ) {
        syslog( LOG_ERR, "open: %s: %m", ci.ci_krbtkt );
        snet_writef( sn, "%d Unable to access %s.\r\n", 547, ci.ci_krbtkt );
        return( 1 );
    }
   
    /* dump file info */

    if ( fstat( fd, &st ) < 0 ) {
        syslog( LOG_ERR, "f_retr: fstat: %m" );
        snet_writef( sn, "%d Access Error: %s\r\n", 548, ci.ci_krbtkt );
        if ( close( fd ) < 0 ) {
            syslog( LOG_ERR, "close: %m" );
            return( -1 );
        }
        return( 1 );
    }

    snet_writef( sn, "%d Retrieving file\r\n", 240 );
    snet_writef( sn, "%d\r\n", (int)st.st_size );

    /* dump file */

    while (( readlen = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv.tv_sec = 60 * 60 ;
        tv.tv_usec = 0;
        if ( snet_write( sn, buf, (int)readlen, &tv ) != readlen ) {
            syslog( LOG_ERR, "snet_write: %m" );
            return( -1 );
        }
    }

    if ( readlen < 0 ) {
        syslog( LOG_ERR, "read: %m" );
        return( -1 );
    }

    snet_writef( sn, ".\r\n" );

    if ( close( fd ) < 0 ) {
        syslog( LOG_ERR, "close: %m" );
        return( -1 );
    }

    syslog( LOG_DEBUG, "f_retr: krbtkt %s retrieved", ci.ci_krbtkt );

    return( 0 );
}


    int
command( fd )
    int			fd;
{
    SNET				*snet;
    int					ac, i;
    char				**av, *line;
    struct timeval			tv;

    srandom( (unsigned)getpid());

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	/* We *could* use write(2) to report an error before we exit here */
	exit( 1 );
    }

    snet_writef( snet, "%d COokie SIGNer ready\r\n", 220 );

    tv.tv_sec = 60 * 10;	/* 10 minutes, should get this from config */
    tv.tv_usec = 0;

    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = 60 * 10;
	tv.tv_usec = 0;
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

	if ( (*(commands[ i ].c_func))( snet, ac, av ) < 0 ) {
	    break;
	}
    }

    if ( line != NULL ) {
	snet_writef( snet,
		"421 Service not available, closing transmission channel\r\n" );
    } else {
	if ( snet_eof( snet )) {
	    syslog( LOG_ERR, "client dropped connection" );
	} else {
	    syslog( LOG_ERR, "snet_getline: %m" );
	}
    }

    exit( 1 );

}

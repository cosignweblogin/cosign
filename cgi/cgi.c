/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <snet.h>
#include "cgi.h"
#include "cosigncgi.h"
#include "network.h"
#include "config.h"
#include "login.h"

#define LOGIN_ERROR_HTML	"../templates/login_error.html"
#define ERROR_HTML	"../templates/error.html"
#define LOGIN_HTML	"../templates/login.html"
#define SERVICE_MENU	"/services/"
#define LOOP_PAGE	"https://weblogin.umich.edu/looping.html"
#define LOOPWINDOW      30 
#define MAXLOOPCOUNT	10	
#define MAXCOOKIETIME	86400	 /* Valid life of session cookie: 24 hours */

extern char	*cosign_version;
char		*cosign_host = _COSIGN_HOST;
char 		*cosign_conf = _COSIGN_CONF;
char		*err = NULL, *ref = NULL, *service = NULL, *login = NULL;
char		*title = "Authentication Required";
char		*cryptofile = _COSIGN_TLS_KEY;
char		*certfile = _COSIGN_TLS_CERT;
char		*cadir = _COSIGN_TLS_CADIR;
SSL_CTX 	*ctx = NULL;

struct cgi_list cl[] = {
#define CL_LOGIN	0
        { "login", NULL },
#define CL_PASSWORD	1
        { "password", NULL },
#define CL_REF		2
        { "ref", NULL },
#define CL_SERVICE	3
        { "service", NULL },
        { NULL, NULL },
};

    static void
subfile( char *filename )
{
    FILE	*fs;
    int 	c, i;
    char	nasties[] = "<>(){}[];'`\" \\";

    fputs( "Cache-Control: no-cache, private\n"
	    "Pragma: no-cache\n"
	    "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Content-type: text/html\n\n", stdout );

    if (( fs = fopen( filename, "r" )) == NULL ) {
	perror( filename );
	exit( 1 );
    }

    while (( c = getc( fs )) != EOF ) {
	if ( c == '$' ) {

	    switch ( c = getc( fs )) {
            case 'c':
                if ( service != NULL ) {
                    for ( i = 0; i < strlen( service ); i++ ) {
                        /* block XSS attacks while printing */
                        if ( strchr( nasties, service[ i ] ) != NULL ||
                                service[ i ] <= 0x1F || service[ i ] >= 0x7F ) {

			    printf( "%%%x", service[ i ] );
                        } else {
                            putc( service[ i ], stdout );
                        }
                    }
                }
                break;

	    case 't':
		if ( title != NULL ) {
		    printf( "%s", title );
		}
		break;

	    case 'e':
		if ( err != NULL ) {
		    printf( "%s", err );
		}
		break;

	    case 'l':
                if ( login != NULL ) {
                    printf( "%s", login );
                }
		break;

	    case 's':
		printf( "%s", getenv( "SCRIPT_NAME" ));
		break;

	    case 'h':
		printf( "%s", cosign_host );
		break;

            case 'k':
		break;

            case 'r':
                if ( ref != NULL ) {
                    for ( i = 0; i < strlen( ref ); i++ ) {
                        /* block XSS attacks while printing */
                        if ( strchr( nasties, ref[ i ] ) != NULL ||
                                ref[ i ] <= 0x1F || ref[ i ] >= 0x7F ) {

			    printf( "%%%x", ref[ i ] );
                        } else {
                            putc( ref[ i ], stdout );
                        }
                    }
                }
                break;

	    case EOF:
		putchar( '$' );
		break;

	    case '$':
		putchar( c );
		break;

	    default:
		putchar( '$' );
		putchar( c );
	    }
	} else {
	    putchar( c );
	}
    }

    if ( fclose( fs ) != 0 ) {
	perror( filename );
    }

    return;
}

    static void
loop_checker( int time, int count, char *cookie )
{
    struct timeval	tv;
    char       		new_cookie[ 255 ];
    char		*tmpl = ERROR_HTML;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	title = "Error: Loop Breaker";
	err = "Please try again later.";
	subfile( tmpl );
	exit( 0 );
    }

    /* we're past our window, all is well */
    if (( tv.tv_sec - time ) > LOOPWINDOW ) {
	time = tv.tv_sec;
	count = 1;
	if ( snprintf( new_cookie, sizeof( new_cookie ),
		"%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
	    title = "Error: Loop Breaker";
	    err = "Please try again later.";
	    subfile( tmpl );
	    exit( 0 );
	}
	printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	return;
    } else {
       /* too many redirects - break the loop and give an error */
       if ( count >= MAXLOOPCOUNT ) {
	    time = tv.tv_sec;
	    count = 1;
	    if ( snprintf( new_cookie, sizeof( new_cookie ),
		    "%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
		title = "Error: Loop Breaker";
		err = "Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }
	    printf( "Location:%s\n\n", LOOP_PAGE );
	    exit( 0 );
	} else {
	    /* we're still in the limit, increment and keep going */
	    count++;
	    if ( snprintf( new_cookie, sizeof( new_cookie ),
		    "%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
		title = "Error: Loop Breaker";
		err = "Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }
	    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	    return;
	}
    }
}

    static void
kcgi_configure()
{
    char 	*val;

    if (( val = cosign_config_get( COSIGNHOSTKEY )) != NULL ) {
	cosign_host = val;
    }
    if (( val = cosign_config_get( COSIGNKEYKEY )) != NULL ) {
	cryptofile = val;
    }
    if (( val = cosign_config_get( COSIGNCERTKEY )) != NULL ) {
	certfile = val;
    }
    if (( val = cosign_config_get( COSIGNCADIRKEY )) != NULL ) {
	cadir = val;
    }
}

    int
main( int argc, char *argv[] )
{
    int				rc, cookietime = 0, cookiecount = 0;
    char                	new_cookiebuf[ 128 ];
    char        		new_cookie[ 255 ];
    char			*data, *ip_addr;
    char			*cookie = NULL, *method, *script, *qs;
    char			*misc = NULL;
    char			*tmpl = LOGIN_HTML;
    struct timeval		tv;
    struct connlist		*head;
    unsigned short		port;

    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    } else if ( argc != 1 ) {
	printf( "usage: %s [-V]\n", argv[ 0 ] );
	exit( 0 );
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	title = "Error: But not your fault";
	err = "We were unable to parse the configuration file";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }
    kcgi_configure();

    method = getenv( "REQUEST_METHOD" );
    script = getenv( "SCRIPT_NAME" );
    ip_addr = getenv( "REMOTE_ADDR" );

    if (( data = getenv( "HTTP_COOKIE" )) != NULL ) {
	for ( cookie = strtok( data, ";" ); cookie != NULL;
		cookie = strtok( NULL, ";" )) {
	    while ( *cookie == ' ' ) ++cookie;
	    if ( strncmp( cookie, "cosign=", 7 ) == 0 ) {
		break;
	    }
	}
    }

    if ( cookie == NULL ) {
	if ( strcmp( method, "POST" ) == 0 ) {
	    title = "Error: Cookies Required";
	    err = "This service requires that cookies be enabled.";
	    tmpl = ERROR_HTML;
	    subfile( tmpl );
	    exit( 0 );
	}
	goto loginscreen;
    }

    if ( strlen( cookie ) < 120 ) {
	goto loginscreen;
    }

    (void)strtok( cookie, "/" );
    if (( misc = strtok( NULL, "/" )) != NULL ) {
	cookietime = atoi( misc );

	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    title = "Error: Login Screen";
	    err = "Please try again later.";
	    subfile( ERROR_HTML );
	    exit( 0 );
	}

	if (( tv.tv_sec - cookietime ) > MAXCOOKIETIME ) {
	    goto loginscreen;
	}
    }

    if (( misc = strtok( NULL, "/" )) != NULL ) {
	cookiecount = atoi( misc );
    }

	/* after here, we have a well-formed cookie */

    /* setup conn and ssl and hostlist */
    port = htons( 6663 );
    if (( head = connlist_setup( cosign_host, port )) == NULL ) {
	title = "Error: But not your fault";
	err = "We were unable to contact the authentication server.  Please try again later.";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx ) != 0 ) {
	title = "Error: But not your fault";
	err = "Failed to initialise connections to the authentication server. Please try again later";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }

    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) && ( *qs != '\0' )) {
	if ((( service = strtok( qs, ";" )) == NULL ) ||
		( strncmp( service, "cosign-", 7 ) != 0 )) {
	    title = "Error: Unrecognized Service";
	    tmpl = ERROR_HTML;
	    err = "Unable to determine referring service from query string.";
	    subfile( tmpl );
	    exit( 0 );
	}

	if ((( ref = strtok( NULL, "" )) == NULL ) || ( *ref != '&' )) {
	    title = "Error: malformatted referrer";
	    tmpl = ERROR_HTML;
	    err = "Unable to determine referring service from query string.";
	    subfile( tmpl );
	    exit( 0 );
	}
	ref++;

	if (( rc = cosign_register( head, cookie, ip_addr, service )) < 0 ) {
	    if ( cosign_check( head, cookie ) < 0 ) {
		err = "You are not logged in. Please log in now.";
		goto loginscreen;
	    }

	    fprintf( stderr, "%s: cosign_register failed\n", script );
	    title = "Error: Register Failed";
	    tmpl = ERROR_HTML;
	    err = "We were unable to contact the authentication server.  Please try again later.";
	    subfile( tmpl );
	    exit( 0 );
	}

	if ( rc > 0 ) {
	    err = "You are not logged in.  Please log in now.";
	    goto loginscreen;
	}

	loop_checker( cookietime, cookiecount, cookie );

	/* if no referrer, redirect to top of site from conf file */
	printf( "Location: %s\n\n", ref );
	exit( 0 );
    }

    if ( strcmp( method, "POST" ) != 0 ) {
	if ( cosign_check( head, cookie ) < 0 ) {
	    err = "You are not logged in. Please log in now.";
	    goto loginscreen;
	}

	/* authentication successful, show service menu */
	printf( "Location: https://%s%s\n\n", cosign_host, SERVICE_MENU );
	exit( 0 );
    }

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	exit( 1 );
    }

    if (( cl[ CL_REF ].cl_data != NULL ) ||
	    ( *cl[ CL_REF ].cl_data != '\0' )) {
        ref = cl[ CL_REF ].cl_data;
    }

    if (( cl[ CL_LOGIN ].cl_data == NULL ) ||
	    ( *cl[ CL_LOGIN ].cl_data == '\0' )) {
	title = "Authentication Required";
	err = "Please enter your login and password.";
        subfile ( tmpl );
	exit( 0 );
    }
    login = cl[ CL_LOGIN ].cl_data;

    if (( cl[ CL_PASSWORD ].cl_data == NULL ) ||
	    ( *cl[ CL_PASSWORD ].cl_data == '\0' )) {
	err = "Unable to login because password is a required field.";
	title = "Missing Password";
	tmpl = LOGIN_ERROR_HTML;
        subfile ( tmpl );
	exit( 0 );
    }

    if ( strchr( login, '@' ) != NULL ) {
# ifdef SQL_FRIEND
	cosign_login_mysql( head, login, cl[ CL_PASSWORD ].cl_data,
		ip_addr, cookie );
#else
	/* no @ unless we're friendly. */
	err = title = "Your login id may not contain an '@'";
	tmpl = LOGIN_ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
# endif
    } else {
	/* not a friend, must be kerberos */
	cosign_login_krb5( head, login, cl[ CL_PASSWORD ].cl_data,
		ip_addr, cookie );
    }

    if (( cl[ CL_SERVICE ].cl_data != NULL ) &&
	    ( *cl[ CL_SERVICE ].cl_data != '\0' )) {

	/* url decode here the service cookie? */

        if (( rc = cosign_register( head, cookie, ip_addr,
		cl[ CL_SERVICE ].cl_data )) < 0 ) {

	    /* this should not be possible... do it anyway? */
            if ( cosign_check( head, cookie ) < 0 ) {
                title = "Authentication Required";
                goto loginscreen;
            }

            fprintf( stderr, "%s: implicit cosign_register failed\n", script );
            title = "Error: Implicit Register Failed";
            tmpl = ERROR_HTML;
            err = "We were unable to contact the authentication server.  Please try again later.";
            subfile( tmpl );
            exit( 0 );
        }
    }

    loop_checker( cookietime, cookiecount, cookie );

    if (( ref != NULL ) && ( ref = strstr( ref, "http" )) != NULL ) {
	printf( "Location: %s\n\n", ref );
	exit( 0 );
    }

    printf( "Location: https://%s%s\n\n", cosign_host, SERVICE_MENU );
    exit( 0 );

loginscreen:
    if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
	fprintf( stderr, "%s: mkcookie: failed\n", script );
	exit( 1 );
    }

    if ( err == NULL ) {
	err = "Please type your login and password and click the Login button to continue.";
    }

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	title = "Error: Login Screen";
	err = "Please try again later.";
	subfile( ERROR_HTML );
	exit( 0 );
    }

    snprintf( new_cookie, sizeof( new_cookie ), "cosign=%s/%d",
	    new_cookiebuf, tv.tv_sec );
    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
    subfile( tmpl );
    exit( 0 );
}

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
#include "subfile.h"

#define LOGIN_ERROR_HTML	"../templates/login_error.html"
#define ERROR_HTML	"../templates/error.html"
#define LOGIN_HTML	"../templates/login.html"
#define SERVICE_MENU	"/services/"
#define LOOPWINDOW      30 
#define MAXLOOPCOUNT	10	
#define MAXCOOKIETIME	86400	 /* Valid life of session cookie: 24 hours */

extern char	*cosign_version;
unsigned short	cosign_port;
char		*cosign_host = _COSIGN_HOST;
char 		*cosign_conf = _COSIGN_CONF;
char		*title = "Authentication Required";
char		*cryptofile = _COSIGN_TLS_KEY;
char		*certfile = _COSIGN_TLS_CERT;
char		*cadir = _COSIGN_TLS_CADIR;
char		*loop_page = _COSIGN_LOOP_URL;
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

static struct subfile_list sl[] = {
#define SL_LOGIN	0
        { 'l', SUBF_STR, NULL },
#define SL_TITLE	1
        { 't', SUBF_STR, NULL },
#define SL_REF		2
        { 'r', SUBF_STR_ESC, NULL },
#define SL_SERVICE	3
        { 'c', SUBF_STR_ESC, NULL },
#define SL_ERROR	4
        { 'e', SUBF_STR, NULL },
        { '\0', 0, NULL },
};

    static void
loop_checker( int time, int count, char *cookie )
{
    struct timeval	tv;
    char       		new_cookie[ 255 ];
    char		*tmpl = ERROR_HTML;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
	sl[ SL_ERROR ].sl_data = "Please try again later.";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    /* we're past our window, all is well */
    if (( tv.tv_sec - time ) > LOOPWINDOW ) {
	time = tv.tv_sec;
	count = 1;
	if ( snprintf( new_cookie, sizeof( new_cookie ),
		"%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
	    sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
	    sl[ SL_ERROR ].sl_data = "Please try again later.";
	    subfile( tmpl, sl, 0 );
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
		sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
		sl[ SL_ERROR ].sl_data = "Please try again later.";
		subfile( tmpl, sl, 0 );
		exit( 0 );
	    }
	    printf( "Location: %s\n\n", loop_page );
	    exit( 0 );
	} else {
	    /* we're still in the limit, increment and keep going */
	    count++;
	    if ( snprintf( new_cookie, sizeof( new_cookie ),
		    "%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
		sl[ SL_TITLE ].sl_data = "Error: Loop Breaker";
		sl[ SL_ERROR ].sl_data = "Please try again later.";
		subfile( tmpl, sl, 0 );
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
    if (( val = cosign_config_get( COSIGNLOOPURLKEY )) != NULL ) {
	 loop_page = val;
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
    if (( val = cosign_config_get( COSIGNPORTKEY )) != NULL ) {
	cosign_port = htons( atoi( val ));
    } else {
	cosign_port = htons( 6663 );
    }
}

    int
main( int argc, char *argv[] )
{
    int				rc, cookietime = 0, cookiecount = 0;
    int				rebasic = 0, len, server_port;
    char                	new_cookiebuf[ 128 ];
    char        		new_cookie[ 255 ];
    char			*data, *ip_addr;
    char			*cookie = NULL, *method, *script, *qs;
    char			*misc = NULL, *p;
    char			*ref = NULL, *service = NULL, *login = NULL;
    char			*remote_user = NULL;
    char			*tmpl = LOGIN_HTML;
    struct timeval		tv;
    struct connlist		*head;

    if ( argc == 2 ) {
	if ( strncmp( argv[ 1 ], "-V", 2 ) == 0 ) {
	    printf( "%s\n", cosign_version );
	    exit( 0 );
	} else if ( strncmp( argv[ 1 ], "basic", 5 ) == 0 ) {
	    rebasic = 1;
	}
    } else if ( argc != 1 ) {
	fprintf( stderr, "usage: %s [-V]\n", argv[ 0 ] );
	exit( 1 );
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "We were unable to parse the "
		"configuration file";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }
    kcgi_configure();


    if (( script = getenv( "SCRIPT_NAME" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Unable to retrieve the script name";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    method = getenv( "REQUEST_METHOD" );
    ip_addr = getenv( "REMOTE_ADDR" );
    remote_user = getenv( "REMOTE_USER" );
    server_port = atoi( getenv( "SERVER_PORT" ));

    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) && ( *qs != '\0' )) {
	if (( p = strtok( qs, "&" )) == NULL ) {
	    sl[ SL_TITLE ].sl_data = "Error: Unrecognized Service";
	    sl[ SL_ERROR ].sl_data = "Unable to determine referring "
		    "service from query string.";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	if ( remote_user && strcmp( p, "basic" ) == 0 ) {
	    rebasic = 1;
	    p = strtok( NULL, "&" );
	}
	
	if ( p != NULL ) {
	    service = p;
	    len = strlen( service );
	    if ( service[ len - 1 ] == ';' ) {
		service[ len - 1 ] = '\0';
	    }
	    if ( strncmp( service, "cosign-", 7 ) != 0 ) {
		sl[ SL_TITLE ].sl_data = "Error: Unrecognized Service";
		sl[ SL_ERROR ].sl_data = "Unable to determine referring "
			"service from query string.";
		tmpl = ERROR_HTML;
		subfile( tmpl, sl, 0 );
		exit( 0 );
	    }
	    sl[ SL_SERVICE ].sl_data = service;

	    if (( ref = strtok( NULL, "" )) == NULL ) {
		sl[ SL_TITLE ].sl_data = "Error: malformatted referrer";
		sl[ SL_ERROR ].sl_data = "Unable to determine referring "
			"service from query string.";
		tmpl = ERROR_HTML;
		subfile( tmpl, sl, 0 );
		exit( 0 );
	    }
	    sl[ SL_REF ].sl_data = ref;
	}
    }

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
	if (( strcmp( method, "POST" ) == 0 ) || rebasic ) {
	    sl[ SL_TITLE ].sl_data = "Error: Cookies Required";
	    sl[ SL_ERROR ].sl_data = "This service requires that "
		    "cookies be enabled.";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
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
	    sl[ SL_TITLE ].sl_data = "Error: Login Screen";
	    sl[ SL_ERROR ].sl_data = "Please try again later.";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
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
    if (( head = connlist_setup( cosign_host, cosign_port )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server.  Please try again later.";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx ) != 0 ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "Failed to initialise connections "
		"to the authentication server. Please try again later";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if ( service != NULL && ref != NULL ) {

	/* basic's implicit register */
	if ( rebasic && cosign_login( head, cookie, ip_addr, remote_user,
		    "basic", NULL ) < 0 ) {
	    fprintf( stderr, "cosign_login: basic login failed\n" ) ;
	    sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		    "authentication server. Please try again later.";
	    sl[ SL_TITLE ].sl_data = "Error: Please try later";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	if (( rc = cosign_register( head, cookie, ip_addr, service )) < 0 ) {
	    if ( cosign_check( head, cookie ) < 0 ) {
		sl[ SL_ERROR ].sl_data = "You are not logged in. "
			"Please log in now.";
		goto loginscreen;
	    }

	    fprintf( stderr, "%s: cosign_register failed\n", script );
	    sl[ SL_TITLE ].sl_data = "Error: Register Failed";
	    sl[ SL_ERROR ].sl_data = "We were unable to contact "
		    "the authentication server.  Please try again later.";
	    tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	/* not possible right now */
	if ( rc > 0 ) {
	    sl[ SL_ERROR ].sl_data = "You are not logged in. "
		    "Please log in now.";
	    fprintf( stderr, "basically not possible\n" ) ;
	    goto loginscreen;
	}

	loop_checker( cookietime, cookiecount, cookie );

	printf( "Location: %s\n\n", ref );
	exit( 0 );
    }

    if ( strcmp( method, "POST" ) != 0 ) {
	if ( cosign_check( head, cookie ) < 0 ) {
	    if ( rebasic && cosign_login( head, cookie, ip_addr, remote_user,
			"basic", NULL ) < 0 ) {
		fprintf( stderr, "cosign_login: basic login failed\n" ) ;
		sl[ SL_ERROR ].sl_data = "We were unable to contact the "
			"authentication server. Please try again later.";
		sl[ SL_TITLE ].sl_data = "Error: Please try later";
		tmpl = ERROR_HTML;
		subfile( tmpl, sl, 0 );
		exit( 0 );
	    } else if ( !rebasic ) {
		sl[ SL_ERROR ].sl_data = "You are not logged in. "
			"Please log in now.";
		goto loginscreen;
	    }
	}

	/* authentication successful, show service menu */
	if ( server_port != 443 ) {
	    printf( "Location: https://%s:%d%s\n\n", cosign_host,
		    server_port, SERVICE_MENU );
	} else {
	    printf( "Location: https://%s%s\n\n", cosign_host, SERVICE_MENU );
	}
	exit( 0 );
    }

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	exit( 1 );
    }

    if (( cl[ CL_REF ].cl_data != NULL ) ||
	    ( *cl[ CL_REF ].cl_data != '\0' )) {
        ref = sl[ SL_REF ].sl_data = cl[ CL_REF ].cl_data;
    }

    if (( cl[ CL_LOGIN ].cl_data == NULL ) ||
	    ( *cl[ CL_LOGIN ].cl_data == '\0' )) {
	sl[ SL_TITLE ].sl_data = "Authentication Required";
	sl[ SL_ERROR ].sl_data = "Please enter your login and password.";
	subfile( tmpl, sl, 1 );
	exit( 0 );
    }
    login = sl[ SL_LOGIN ].sl_data = cl[ CL_LOGIN ].cl_data;

    if (( cl[ CL_PASSWORD ].cl_data == NULL ) ||
	    ( *cl[ CL_PASSWORD ].cl_data == '\0' )) {
	sl[ SL_TITLE ].sl_data = "Missing Password";
	sl[ SL_ERROR ].sl_data = "Unable to login because password is "
		"a required field.";
	tmpl = LOGIN_ERROR_HTML;
	subfile( tmpl, sl, 1 );
	exit( 0 );
    }

    if ( strchr( login, '@' ) != NULL ) {
# ifdef SQL_FRIEND
	cosign_login_mysql( head, login, cl[ CL_PASSWORD ].cl_data,
		ip_addr, cookie, ref, service );
# else
	/* no @ unless we're friendly. */
	sl[ SL_ERROR ].sl_data = sl[ SL_TITLE ].sl_data = "Your login id may not contain an '@'";
	tmpl = LOGIN_ERROR_HTML;
	subfile( tmpl, sl, 1 );
	exit( 0 );

# endif  /* SQL_FRIEND */
    } else {
# ifdef KRB
	/* not a friend, must be kerberos */
	cosign_login_krb5( head, login, cl[ CL_PASSWORD ].cl_data,
		ip_addr, cookie, ref, service );
# else /* KRB */
	sl[ SL_TITLE ].sl_data = "Error: Server Configuration";
	sl[ SL_ERROR ].sl_data = "No Login Method Configured";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
# endif /* KRB */
    }

    if (( cl[ CL_SERVICE ].cl_data != NULL ) &&
	    ( *cl[ CL_SERVICE ].cl_data != '\0' )) {

	/* url decode here the service cookie? */
	service = sl[ SL_SERVICE ].sl_data = cl[ CL_SERVICE ].cl_data;

        if (( rc = cosign_register( head, cookie, ip_addr, service )) < 0 ) {
	    /* this should not be possible... do it anyway? */
            if ( cosign_check( head, cookie ) < 0 ) {
                sl[ SL_TITLE ].sl_data = "Authentication Required";
                goto loginscreen;
            }

            fprintf( stderr, "%s: implicit cosign_register failed\n", script );
            sl[ SL_TITLE ].sl_data = "Error: Implicit Register Failed";
            sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		    "authentication server.  Please try again later.";
            tmpl = ERROR_HTML;
	    subfile( tmpl, sl, 0 );
            exit( 0 );
        }
    }

    loop_checker( cookietime, cookiecount, cookie );

    if (( ref != NULL ) && ( ref = strstr( ref, "http" )) != NULL ) {
	printf( "Location: %s\n\n", ref );
	exit( 0 );
    }

    if ( server_port != 443 ) {
	printf( "Location: https://%s:%d%s\n\n", cosign_host,
		server_port, SERVICE_MENU );
    } else {
	printf( "Location: https://%s%s\n\n", cosign_host, SERVICE_MENU );
    }
    exit( 0 );

loginscreen:
    if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
	fprintf( stderr, "%s: mkcookie: failed\n", script );
	exit( 1 );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	sl[ SL_TITLE ].sl_data = "Error: Login Screen";
	sl[ SL_ERROR ].sl_data = "Please try again later.";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    snprintf( new_cookie, sizeof( new_cookie ), "cosign=%s/%lu",
	    new_cookiebuf, tv.tv_sec );
    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );

    if ( remote_user ) {
	if ( server_port != 443 ) {
	    printf( "Location: https://%s:%d%s?basic",
		    cosign_host, server_port, script );
	} else {
	    printf( "Location: https://%s%s?basic", cosign_host, script );
	}
	if (( ref != NULL ) && ( service != NULL )) {
	    printf( "&%s&%s\n\n", service, ref );
	} else {
	    fputs( "\n\n", stdout );
	}
    } else {
	if ( sl[ SL_ERROR ].sl_data == NULL ) {
	    sl[ SL_ERROR ].sl_data = "Please type your login and password "
		    "and click the Login button to continue.";
	}
	subfile( tmpl, sl, 1 );
    }
    exit( 0 );
}

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
#include <openssl/ssl.h>
#include <snet.h>
#include "cgi.h"
#include "cosigncgi.h"
#include "network.h"
#include "config.h"

#define ERROR_HTML	"../templates/error.html"
#define REDIRECT_HTML	"../templates/redirect.html"
#define SERVICE_MENU    "../templates/service-menu.html"
#define VERIFY_LOGOUT   "../templates/verify-logout.html"

extern char	*cosign_version;
char		*err = NULL;
char		*title = "Logout";
char		*title = "Logout";
char		*script = "/cgi-bin/logout";
char		*cosign_host =_COSIGN_HOST;
char		*url = _COSIGN_LOGOUT_URL;
char    	*certfile = _COSIGN_TLS_CERT;
char		*cryptofile = _COSIGN_TLS_KEY;
char		*cadir =_COSIGN_TLS_CADIR;
char		*cosign_conf = _COSIGN_CONF;

unsigned short	cosign_port = htons( 6663 );
SSL_CTX         *ctx = NULL;
int		nocache = 0;


struct cgi_list cl[] = {
#define CL_VERIFY	0
        { "verify", NULL },
#define CL_URL 		1
        { "url", NULL },
        { NULL, NULL },
};


    void
subfile( char *filename )
{
    FILE	*fs;
    int 	c, i;
    char	nasties[] = "<>(){}[]~?&=;'`\" \\";

    if ( nocache ) {
	fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Cache-Control: no-store, no-cache, must-revalidate\n"
		"Cache-Control: pre-check=0, post-check=0, max-age=0\n"
		"Pragma: no-cache\n", stdout );
    }

    fputs( "Content-type: text/html\n\n", stdout );

    if (( fs = fopen( filename, "r" )) == NULL ) {
	perror( filename );
	exit( 1 );
    }

    while (( c = getc( fs )) != EOF ) {
	if ( c == '$' ) {

	    switch ( c = getc( fs )) {
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

	    case 's':
		printf( "%s", script );
		break;

            case 'u':
                if ( url != NULL ) {
		    for ( i = 0; i < strlen( url ); i++ ) {
			/* block XSS attacks while printing */
			if ( strchr( nasties, url[ i ] ) != NULL ||
				url[ i ] <= 0x1F || url[ i ] >= 0x7F ) {
			    printf( "%%%x", url[ i ] );
			} else {
			    putc( url[ i ], stdout );
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
logout_configure()
{
    char	 *val;

    if (( val = cosign_config_get( COSIGNHOSTKEY )) != NULL ) {
        cosign_host = val;
    }
    if (( val = cosign_config_get( COSIGNLOGOUTURLKEY )) != NULL ) {
	url = val;
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
    }
}

    int
main( int argc, char *argv[] )
{
    char		*tmpl = VERIFY_LOGOUT;
    char		*cookie = NULL, *data, *ip_addr, *qs;
    struct connlist	*head;

    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    }

    if (( ip_addr = getenv( "REMOTE_ADDR" )) == NULL ) {
        title = "Error: Server Error";
        err = "REMOTE_ADDR not set";
        tmpl = ERROR_HTML;
        subfile( tmpl );
	exit( 0 );
    }

    if (( script = getenv( "SCRIPT_NAME" )) == NULL ) {
        title = "Error: Server Error";
        err = "SCRIPT_NAME not set";
        tmpl = ERROR_HTML;
        subfile( tmpl );
	exit( 0 );
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
        title = "Error: System Error";
        err = "We were unable to parse the configuration file";
        tmpl = ERROR_HTML;
        subfile( tmpl );
        exit( 0 );
    }
    logout_configure();

    if ( cgi_info( CGI_GET, cl ) == 0 ) {
	/* this is not a POST, display verify screen */
	if ((( qs = getenv( "QUERY_STRING" )) != NULL ) &&
		( *qs != '\0' ) &&
		( strncmp( qs, "http", 4 ) == 0 )) {

	    /* query string looks like a url preserve it */
	    url = strdup( qs );
	}

	title = "Logout Requested";

	subfile ( tmpl );
	exit( 0 );
    }

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	/* an actual logout must be the result of a POST, see? */
        fprintf( stderr, "%s: cgi_info failed\n", script );
        exit( 1 );
    }

    if (( cl[ CL_VERIFY ].cl_data == NULL ) ||
	    ( *cl[ CL_VERIFY ].cl_data == '\0' )) {
	/* user clicked a submit button but not the one named 'Verify' */
	printf( "Location: https://%s/\n\n", cosign_host );
	exit( 0 );
    }

    if (( cl[ CL_URL ].cl_data != NULL ) ||
	    ( *cl[ CL_URL ].cl_data != '\0' )) {
	/* oh the places you'll go */
        if ( strncmp( cl[ CL_URL ].cl_data, "http", 4 ) == 0 ) {
	    url = cl[ CL_URL ].cl_data;
	}
    }

    /* read user's cosign cookie and LOGOUT */
    if (( data = getenv( "HTTP_COOKIE" )) != NULL ) {
        cookie = strtok( data, ";" );
        if ( strncmp( cookie, "cosign=", 7 ) != 0 ) {
            while (( cookie = strtok( NULL, ";" )) != NULL ) {
                if ( *cookie == ' ' ) ++cookie;
                if ( strncmp( cookie, "cosign=", 7 ) == 0 ) {
                    break;
                }
            }
        }
    }
    /* only the cosign= cookie and not the loop breaking info */
    (void)strtok( cookie, "/" );

    /* clobber the cosign cookie */
    fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Cache-Control: no-store, no-cache, must-revalidate\n"
	    "Cache-Control: pre-check=0, post-check=0, max-age=0\n"
	    "Pragma: no-cache\n", stdout );

    fputs( "Set-Cookie: cosign=null; path=/; expires=Wednesday, 16-Apr-73 02:10:00 GMT; secure\n", stdout );

    /* setup conn and ssl and hostlist to tell cosignd we're logged out */
    if (( head = connlist_setup( cosign_host, cosign_port )) == NULL ) {
        title = "Error: But not your fault";
        err = "We were unable to contact the authentication server.  Please quit your web browser to complete logout.";
        tmpl = ERROR_HTML;
        subfile( tmpl );
        exit( 0 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx )) {
        title = "Error: But not your fault";
        err = "Failed to initialise connections to the authentication server. Please quit your browser to complete logout.";
        tmpl = ERROR_HTML;
        subfile( tmpl );
        exit( 0 );
    }

    if ( cookie != NULL ) {
	if ( cosign_logout( head, cookie, ip_addr ) < 0 ) {
	    fprintf( stderr, "%s: logout failed\n", script ) ;

	    /* the user doesn't care that logout failed, as long as the
		cookie gets expired.  We could log user's IP and cookie
		string in the error log, but I think that's just
		useless noise so I'm going to just ignore this case
		altogether.  -- clunis
	    */
	}
    }

    printf( "Location: %s\n\n", url );
    exit( 0 );
}

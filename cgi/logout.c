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
#include <openssl/ssl.h>
#include <snet.h>
#include "cgi.h"
#include "cosigncgi.h"
#include "network.h"

#define ERROR_HTML	"../templates/error.html"
#define REDIRECT_HTML	"../templates/redirect.html"
#define SERVICE_MENU    "../templates/service-menu.html"
#define VERIFY_LOGOUT   "../templates/verify-logout.html"
#define SIDEWAYS	1

extern char	*cosign_version;
char	*err = NULL;
char	*title = "Logout";
char	*host = _COSIGN_HOST;
char	*url = _COSIGN_LOGOUT_URL;
int	port = 6663;
int	nocache = 0;

struct cgi_list cl[] = {
#define CL_VERIFY	0
        { "verify", NULL },
#define CL_URL 		1
        { "url", NULL },
        { NULL, NULL },
};

void	subfile( char * );


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
	exit( SIDEWAYS );
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
		printf( "%s", getenv( "SCRIPT_NAME" ));
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


    int
main( int argc, char *argv[] )
{
    char	*tmpl = VERIFY_LOGOUT;
    char	*cookie = NULL, *data, *ip_addr, *script, *qs;

    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    }

    if ( cgi_info( CGI_GET, cl ) == 0 ) {
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

    ip_addr = getenv( "REMOTE_ADDR" );
    script = getenv( "SCRIPT_NAME" );

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	/* an actual logout must be the result of a POST, see? */
        fprintf( stderr, "%s: cgi_info failed\n", script );
        exit( SIDEWAYS );
    }

    if (( cl[ CL_VERIFY ].cl_data == NULL ) ||
	    ( *cl[ CL_VERIFY ].cl_data == '\0' )) {
	/* user posted, but did not verify */
	printf( "Location: https://%s/\n\n", host );

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

    if ( cookie != NULL ) {
	fprintf( stderr, "LOGOUT %s %s\n", cookie, ip_addr );
	if ( cosign_logout( cookie, ip_addr ) < 0 ) {
	    fprintf( stderr, "%s: logout failed\n", script ) ;

	    err = "Logout failed.  Perhaps you were not logged-in?";
	    title = "Error:  Logout Failed";
	    tmpl = ERROR_HTML;

	    subfile( tmpl );
	    exit( 2 );
	}
    }

    /* clobber the cosign cookie and display logout screen */
    fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Cache-Control: no-store, no-cache, must-revalidate\n"
	    "Cache-Control: pre-check=0, post-check=0, max-age=0\n"
	    "Pragma: no-cache\n", stdout );

    fputs( "Set-Cookie: cosign=null; path=/; expires=Wednesday, 16-Apr-73 02:10:00 GMT; secure\n", stdout );

    printf( "Location: %s\n\n", url );
    exit( 0 );
}

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
#define SIDEWAYS	1
#define htputs( x ) fputs((x),stdout);

extern char	*version;
char	*err = NULL;
char	*title = "Logout";
char	*url = "http://www.umich.edu/";
char	*host = "weblogin.umich.edu";
int	port = 6663;
int	nocache = 0;

struct cgi_list cl[] = {
#define CL_UNIQNAME	0
        { "uniqname", NULL },
#define CL_PASSWORD	1
        { "password", NULL },
        { NULL, NULL },
};

void	(*logger)( char * ) = NULL;
void	subfile( char * );


    void
subfile( char *filename )
{
    FILE	*fs;
    int 	c;

    if ( nocache ) {
	fputs( "Cache-Control: private, must-revalidate, no-cache\n"
	       "Expires: Mon, 16 Apr 1973 02:10:00 GMT\n"
	       "Pragma: no cache\n", stdout );
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

	    case 'u':
                if (( cl[ CL_UNIQNAME ].cl_data != NULL ) &&
                        ( *cl[ CL_UNIQNAME ].cl_data != '\0' )) {
                    printf( "%s", cl[ CL_UNIQNAME ].cl_data );
                }
		break;

	    case 's':
		printf( "%s", getenv( "SCRIPT_NAME" ));
		break;

            case 'l':
                if ( url != NULL ) {
                    printf( "%s", url );
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
    char	*tmpl = REDIRECT_HTML;
    char	*cookie = NULL, *data, *ip_addr, *script, *qs;

    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", version );
	exit( 0 );
    }

    if ( cgi_info( CGI_GET, cl ) != 0 ) {
	fprintf( stderr, "%s: cgi_info broken\n", getenv( "SCRIPT_NAME" ) );
	exit( 1 );
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

    ip_addr = getenv( "REMOTE_ADDR" );
    script = getenv( "SCRIPT_NAME" );

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
    fputs( "Set-Cookie: cosign=; path=/; expires=Wednesday, 16-Apr-73 02:10:00 GMT; secure\n", stdout );

    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) &&
	    ( *qs != '\0' ) &&
	    ( strncmp( qs, "http", 4 ) == 0 )) {

	/* query string looks like a url, redirect to it */
	url = strdup( qs );
    }

    htputs( "Cache-Control: private, must-revalidate, no-cache\n"
            "Expires: Mon, 16 Apr 1973 02:10:00 GMT\n"
            "Pragma: no cache\n" );

    title = "Logout Successful";
    err = "You have successfully logged out.  In a moment your browser will be redirected to:";
    nocache = 1;
    subfile ( tmpl );

    exit( 0 );
}

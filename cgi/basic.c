/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <snet.h>
#include "cosigncgi.h"
#include "network.h"

#define ERROR_HTML	"../templates/error.html"
#define SERVICE_MENU	"../templates/service-menu.html"
#define SIDEWAYS        1

extern char	*cosign_version;
char	*err = NULL, *ref = NULL, *service = NULL;
char	*title = "Authentication Required";
char	*cosign_host = _COSIGN_HOST;
int	port = 6663;


void            subfile( char * );

    void
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
	exit( SIDEWAYS );
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

	    case 'u':
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


    int
main( int argc, char *argv[] )
{
    char			*user = NULL;
    int				rc;
    char                	new_cookiebuf[ 128 ];
    char        		new_cookie[ 255 ];
    char			*data, *ip_addr;
    char			*cookie = NULL, *method, *script, *qs;
    char			*tmpl = ERROR_HTML;
    struct connlist             *head;


    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    }

    if (( user = getenv( "REMOTE_USER" )) == NULL ) {
	title = "Error: No Remote User";
	tmpl = ERROR_HTML;
	err = "Unable to determine a user. You must not have logged in.";
	subfile( tmpl );
	exit( 0 );
    }


    if (( data = getenv( "HTTP_COOKIE" )) != NULL ) {
	cookie = strtok( data, ";" );

	/* nibble away the cookie string until we see the cosign= cookie */
	if ( strncmp( cookie, "cosign=", 7 ) != 0 ) {
	    while (( cookie = strtok( NULL, ";" )) != NULL ) {
		if ( *cookie == ' ' ) ++cookie;
		if ( strncmp( cookie, "cosign=", 7 ) == 0 ) {
		    break;
		}
	    }
	}
    }

    method = getenv( "REQUEST_METHOD" );
    script = getenv( "SCRIPT_NAME" );
    ip_addr = getenv( "REMOTE_ADDR" );

    if ( strcmp( method, "POST" ) == 0 ) {
	title = "Error: No Posting allowed!";
	err = "You shouldn't be posting!";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }

    if (( head = connlist_setup( cosign_host, port )) == NULL ) {
	title = "Error: But not your fault";
	err = "We were unable to contact the authentication server.  Please try again later.";     
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }

    ssl_setup();

    /* this is a register, and we implicitly log them in if need be */
    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) && ( *qs != '\0' )) {
	if ((( service = strtok( qs, ";" )) == NULL ) ||
		( strncmp( service, "cosign-", 7 ) != 0 )) {
	    title = "Error: Unrecognized Service";
	    tmpl = ERROR_HTML;
	    err = "Unable to determine referring service from query string.";
	    subfile( tmpl );
	    exit( 0 );
	}
	if ( strlen( service ) > MAXNAMELEN ) {
	    tmpl = ERROR_HTML;
	    title = "Error: Max Length Exceeded";
	    err = "An error occurred while processing your request:  max length exceeded.";
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

	if ( cookie == NULL || strlen( cookie ) < 120 ) {
	    if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
		fprintf( stderr, "%s: mkcookie: failed\n", script );
		exit( SIDEWAYS );
	    }
	    snprintf( new_cookie, sizeof( new_cookie ),
		    "cosign=%s", new_cookiebuf );
	    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	    cookie = new_cookie;
	    if ( cosign_login( head, cookie, ip_addr, user, "basic", NULL )
		    < 0 ) {
		fprintf( stderr, "%s: login failed\n", script ) ;
		title = "Error: Login Failed";
		tmpl = ERROR_HTML;
		err = "We were unable to contact the authentication server.  Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }
	}

	if (( rc = cosign_register( head, cookie, ip_addr, service )) < 0 ) {
	    fprintf( stderr, "%s: cosign_register failed\n", script );
	    title = "Error: Register Failed";
	    tmpl = ERROR_HTML;
	    err = "We were unable to contact the authentication server.  Please try again later.";
	    subfile( tmpl );
	    exit( 0 );
	}

	if ( rc > 0 ) {
	    /* log them in */
	    if ( cosign_login( head, cookie, ip_addr, user, "basic", NULL )
		    < 0 ) {
		fprintf( stderr, "%s: login failed\n", script ) ;
		title = "Error: Login Failed";
		tmpl = ERROR_HTML;
		err = "We were unable to contact the authentication server.  Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }

	    if (( rc = cosign_register( head, cookie, ip_addr, service )) < 0 ) {
		fprintf( stderr, "%s: cosign_register failed\n", script );
		title = "Error: Register Failed";
		tmpl = ERROR_HTML;
		err = "We were unable to contact the authentication server.  Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }
	}

	/* if no referrer, redirect to top of site from conf file */
	printf( "Location: %s\n\n", ref );
	exit( 0 );
    }

    if ( cookie == NULL ) {
	if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
	    fprintf( stderr, "%s: mkcookie: failed\n", script );
	    exit( SIDEWAYS );
	}
	snprintf( new_cookie, sizeof( new_cookie ),
		"cosign=%s", new_cookiebuf );
	printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	if ( cosign_login( head, new_cookie, ip_addr, user, "basic", NULL )
		< 0 ) {
	    fprintf( stderr, "%s: login failed\n", script ) ;
	    title = "Error: Login Failed";
	    tmpl = ERROR_HTML;
	    err = "We were unable to contact the authentication server.  Please try again later.";
	    subfile( tmpl );
	    exit( 0 );
	}

	title = "Authentication Successful";
	tmpl = SERVICE_MENU;
	subfile( tmpl );
	exit( 0 );
    }

    if ( cosign_check( head, cookie ) < 0 ) {
	if ( cosign_login( head, new_cookie, ip_addr, user, "basic", NULL )
		< 0 ) {
	    fprintf( stderr, "%s: login failed\n", script ) ;
	    title = "Error: Login Failed";
	    tmpl = ERROR_HTML;
	    err = "We were unable to contact the authentication server.  Please try again later.";
	    subfile( tmpl );
	    exit( 0 );
	}
    }
    title = "Authentication Successful";
    tmpl = SERVICE_MENU;
    subfile( tmpl );
    exit( 0 );
}

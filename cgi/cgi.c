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
#include <krb5.h>
#include <snet.h>
#include "cgi.h"
#include "cosigncgi.h"
#include "network.h"

#define ERROR_HTML	"../templates/error.html"
#define LOGIN_HTML	"../templates/login.html"
#define REDIRECT_HTML	"../templates/redirect.html"
#define SERVICE_MENU	"../templates/service-menu.html"
#define SPLASH_HTML	"../templates/splash.html"
#define SIDEWAYS        1

char	*err = NULL;
char	*url = "http://www.umich.edu/";
char	*title = "Authentication Required";
char	*host = "cosign-test.www.umich.edu";
int	nocache = 0;
int	port = 6663;

struct cgi_list cl[] = {
#define CL_UNIQNAME	0
        { "uniqname", NULL },
#define CL_PASSWORD	1
        { "password", NULL },
        { NULL, NULL },
};

void            (*logger)( char * ) = NULL;

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
main()
{
    krb5_error_code		kerror;
    krb5_context		kcontext;
    krb5_principal		kprinc;
    krb5_get_init_creds_opt	kopts;
    krb5_creds			kcreds;
    int				rc;
    char                	new_cookiebuf[ 128 ];
    char        		new_cookie[ 255 ];
    char			*data, *ip_addr, *service, *ref;
    char			*cookie = NULL, *method, *script, *qs;
    char			*tmpl = LOGIN_HTML;

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

    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) && ( *qs != '\0' )) {
	service = strtok( qs, ";" );
	ref = strtok( NULL, "&" );

	printf( "Set-Cookie: cosign-referrer=%s; path=/; secure\n", ref );

	if ( cookie == NULL || strlen( cookie ) == 7 ) {
	    title = "Authentication Required";
	    tmpl = SPLASH_HTML;
	    subfile( tmpl );
	    exit( 0 );
	}

	if ( strncmp( service, "cosign-", 7 ) != 0 ) {
	    title = "Error: Unrecognized Service";
	    tmpl = ERROR_HTML;
	    err = "Unable to determine referring service from query string.";
	    subfile( tmpl );
	    exit( 0 );
	}

	if ( strlen( service ) > MAXPATHLEN ) {
	    tmpl = ERROR_HTML;
	    title = "Error: Max Length Exceeded";
	    err = "An error occurred while processing your request:  max length exceeded.";
	    subfile( tmpl );
	    exit( 0 );
	}

	if (( rc = cosign_register( cookie, ip_addr, service )) < 0 ) {
	    if ( cosign_check( cookie ) < 0 ) {
		title = "Authentication Required";
		tmpl = SPLASH_HTML;
		subfile( tmpl );
		exit( 0 );
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

	/* when would we ever get here?  -- clunis */
	printf( "Location: %s\n\n", ref );
	exit( 0 );

	/* if no referrer, redirect to top of site from conf file */
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

    /* no query string, yes cookie -- IP? */

    if ( strcmp( method, "POST" ) != 0 ) {
	if ( cosign_check( cookie ) < 0 ) {
	    /* fprintf( stderr, "no longer logged in\n" ); */
	    err = "You are not logged in. Please log in now.";
	    goto loginscreen;
	}

	title = "Authentication Successful";
	tmpl = SERVICE_MENU;
	nocache = 1;

	subfile( tmpl );
	exit( 0 );
    }

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	fprintf( stderr, "%s: cgi_info failed\n", script );
	exit( SIDEWAYS );
    }

    if (( cl[ CL_UNIQNAME ].cl_data == NULL ) ||
	    ( *cl[ CL_UNIQNAME ].cl_data == '\0' )) {
	title = "Authentication Required";
	err = "Please enter your uniqname and password.";
        subfile ( tmpl );
	exit( 0 );
    }

    if (( cl[ CL_PASSWORD ].cl_data == NULL ) ||
	    ( *cl[ CL_PASSWORD ].cl_data == '\0' )) {
	err = "Unable to login because password is a required field.";
	title = "Authentication Required ( missing password )";

        subfile ( tmpl );
	exit( 0 );
    }

    if (( kerror = krb5_init_context( &kcontext ))) {
	err = (char *)error_message( kerror );
	title = "Authentication Required ( kerberos error )";

	tmpl = ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
    }

    if (( kerror = krb5_parse_name( kcontext, cl[ CL_UNIQNAME ].cl_data,
	    &kprinc ))) {
	err = (char *)error_message( kerror );
	title = "Authentication Required ( kerberos error )";

	tmpl = ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, 5*60 );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 0 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    if (( kerror = krb5_get_init_creds_password( kcontext, &kcreds, 
	    kprinc, cl[ CL_PASSWORD ].cl_data, krb5_prompter_posix, NULL, 0, 
	    "kadmin/changepw", &kopts ))) {

	if ( kerror == KRB5KRB_AP_ERR_BAD_INTEGRITY ) {

	    err = "Password incorrect.  Is [caps lock] on?";
	    title = "Authentication Required ( Password Incorrect )";

	    subfile ( tmpl );
	    exit( 0 );
	} else {
	    err = (char *)error_message( kerror );
	    title = "( Password Error )";
	    
	    subfile ( tmpl );
	    exit( 0 );
	}
    }

    /* password has been accepted, tell cosignd */
    err = "Your password has been accepted.";
    title = "Choose a Service";
    tmpl = SERVICE_MENU;
    nocache = 1;

    /* what happens when we get an already logged in back? tri-val? */
    if ( cosign_login( cookie, ip_addr, 
	    cl[ CL_UNIQNAME ].cl_data, "UMICH.EDU" ) < 0 ) {
	fprintf( stderr, "%s: login failed\n", script ) ;
	err = "Login failed: Sorry!";
	title = "Error: Authentication Failed";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 2 );
    }

    if (( data = getenv( "HTTP_COOKIE" )) != NULL ) {
	ref = strtok( data, ";" );

	/* nibble away the cookie string until we see the referrer cookie */
	if ( strncmp( ref, "cosign-referrer=", 15 ) != 0 ) {
	    while (( ref = strtok( NULL, ";" )) != NULL ) {
		if ( *ref == ' ' ) ++ref;
		if ( strncmp( ref, "cosign-referrer=", 15 ) == 0 ) {
		    break;
		}
	    }
	}
    }

    if (( ref != NULL ) && ( ref = strstr( ref, "http" )) != NULL ) {
	url = strdup( ref );
	title = "Authentication Successful";
	err = "Authentication succeeded.  In a moment your browser will be redirected to:";
	tmpl = REDIRECT_HTML;
	nocache = 1;

	/* clobber the referrer cookie */
	fputs( "Set-Cookie: cosign-referrer=; path=/; secure\n", stderr );
    }

    subfile( tmpl );
    exit( 0 );

loginscreen:

    if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
	fprintf( stderr, "%s: mkcookie: failed\n", script );
	exit( SIDEWAYS );
    }

    sprintf( new_cookie, "cosign=%s", new_cookiebuf );
    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
    nocache = 1;
    subfile( tmpl );
    exit( 0 );
}

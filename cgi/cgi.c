/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
*/

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <krb5.h>
#include <snet.h>
#include "cgi.h"

#define HOST		"beothuk.web.itd.umich.edu"
#define PORT		6663
#define LOGIN_HTML	"../html-ssl/login.html"
#define ERROR_HTML	"../html-ssl/error.html"
#define htputs( x ) fputs((x),stdout);

char			*err = NULL;
char			*url = "http://www.umich.edu/";
char			*title = NULL;
struct timeval          timeout = { 10 * 60, 0 };

struct cgi_list cl[] = {
#define CL_UNIQNAME	0
        { "uniqname", NULL },
#define CL_PASSWORD	1
        { "password", NULL },
        { NULL, NULL },
};


    void
subfile( char *filename )
{
    FILE	*fs;
    int 	c;

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

	    case 'u':
                if (( cl[ CL_UNIQNAME ].cl_data != NULL ) &&
                        ( *cl[ CL_UNIQNAME ].cl_data != '\0' )) {
                    printf( "%s", cl[ CL_UNIQNAME ].cl_data );
                }
		break;

	    case 's':
		printf( "%s", getenv( "SCRIPT_NAME" ) );
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
    krb5_data			kd_rcs, kd_rs;
    int				port = PORT;
    char 			*host = HOST;
    int				i, s;
    struct hostent		*he;
    struct sockaddr_in		sin;
    struct timeval		tv;
    SNET			*sn = NULL;
    char			*line;
    char                	cookiebuf[ 128 ];
    char        		cookie[ 255 ];
    char			*tmpl = LOGIN_HTML;

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	fprintf( stderr, "%s: cgi_info broken\n", getenv( "SCRIPT_NAME" ) );
	exit( 1 );
    }

    if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
	fprintf( stderr, "unable to generate new cookie!\n" );
	tmpl = ERROR_HTML;
	err = "Unable to generate new cookie.  Please reload this screen to try again.";
	goto dispage;
    }

    sprintf( cookie, "cosign=%s", cookiebuf );

    printf( "Set-Cookie: %s; path=/; secure\n", cookie );
    htputs( "Cache-Control: private, must-revalidate, no-cache\n"
            "Expires: Mon, 16 Apr 1973 02:10:00 GMT\n"
            "Pragma: no cache\n" );

    if (( cl[ CL_UNIQNAME ].cl_data == NULL ) ||
	    ( *cl[ CL_UNIQNAME ].cl_data == '\0' )) {

        if ( strcmp( getenv( "REQUEST_METHOD" ), "GET" ) != 0 ) {
            err = "Please enter your uniqname and password.";
        }

        goto dispage;
    }

    if (( cl[ CL_PASSWORD ].cl_data == NULL ) ||
	    ( *cl[ CL_PASSWORD ].cl_data == '\0' )) {
	err = "Unable to login because password is a required field.";
	title = "( missing password )";

        goto dispage;
    }

    /* only the POST method may be used to login */
    if ( strcmp( getenv( "REQUEST_METHOD" ), "GET" ) == 0 ) {
	err = "Please enter your uniqname and password.";

        goto dispage;
    }

    if (( kerror = krb5_init_context( &kcontext ))) {
	err = (char *)error_message( kerror );
	title = "( kerberos error )";

	tmpl = ERROR_HTML;
	goto dispage;
    }

    if (( kerror = krb5_parse_name( kcontext, cl[ CL_UNIQNAME ].cl_data, &kprinc ))) {
	err = (char *)error_message( kerror );
	title = "( kerberos error )";

	tmpl = ERROR_HTML;
	goto dispage;
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
	    title = "( Password Incorrect )";

	    goto dispage;
	} else {
	    err = (char *)error_message( kerror );
	    title = "( Password Error )";
	    
	    goto dispage;
	}
    }

    krb5_free_data_contents( kcontext, &kd_rs );
    krb5_free_data_contents( kcontext, &kd_rcs );

    /* password has been accepted, tell cosignd */
    err = "Your password has been accepted.";
    title = "Succeeded";
    tmpl = ERROR_HTML;

    memset( &sin, 0, sizeof( struct sockaddr_in ));
    sin.sin_family = AF_INET;
    sin.sin_port = port;

    if (( he = gethostbyname( host )) == NULL ) {
	fprintf( stderr, "%s: Unknown host\n", host );
	goto dispage;
    }

    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
        memcpy( &sin.sin_addr.s_addr, he->h_addr_list[ i ],
                ( unsigned int)he->h_length );

	fprintf( stderr, "everything is ready to connect to %s\n", host );

	if (( s = socket( PF_INET, SOCK_STREAM, NULL )) < 0 ) {
	    /* this should not actually be fatal */
	    perror( "socket" );
	    exit( 1 );    
	}

	fprintf( stderr, "trying %s... ", host );

	if ( connect( s, (struct sockaddr *)&sin, sizeof( struct sockaddr_in ) ) != 0 ) {

	    fprintf( stderr,  "failed: %s\n", strerror( errno ));
	    (void)close( s );
	    goto dispage;
	}
	fputs( "success!\n", stderr );

	if ( ( sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	    perror( "snet_attach" );
	    exit( 1 );  
	}

	tv = timeout;

	if ( ( line = snet_getline( sn, &tv) ) == NULL ) {
	    fprintf( stderr, "connection to %s failed: %s\n", host, strerror( errno ));
	    snet_close( sn );
	    goto dispage;
	}

	fprintf( stderr, "S: %s\n", line);

	snet_writef( sn, "login %s %s %s UMICH.EDU\r\n",
		cookiebuf, getenv( "REMOTE_ADDR" ), cl[ CL_UNIQNAME ].cl_data );
	fprintf( stderr, "C: login %s %s %s UMICH.EDU\n",
		cookiebuf, getenv( "REMOTE_ADDR" ), cl[ CL_UNIQNAME ].cl_data );

	if ( ( line = snet_getline( sn, &tv) ) == NULL ) {
	    fprintf( stderr, "connection to %s failed: %s\n", host, strerror( errno ));
	    snet_close( sn );
	    goto dispage;
	}
	fprintf( stderr, "S: %s\n", line);

	snet_writef( sn, "quit\r\n",
		cookiebuf, cl[ CL_UNIQNAME ].cl_data );
	fprintf( stderr, "C: quit\n",
		cookiebuf, cl[ CL_UNIQNAME ].cl_data );

	if ( ( line = snet_getline( sn, &tv) ) == NULL ) {
	    fprintf( stderr, "connection to %s failed: %s\n", host, strerror( errno ));
	    snet_close( sn );
	    goto dispage;
	}
	fprintf( stderr, "S: %s\n", line);

	snet_close( sn );     
	goto dispage;
    }

dispage:
    subfile ( tmpl );

    exit( 0 );
}

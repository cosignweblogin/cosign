/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
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
#define ERROR_HTML	"../html-ssl/error.html"
#define LOGOUT_HTML	"../html-ssl/logout.html"
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
#define CL_LINK		2
        { "link", NULL },
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
    char			*tmpl = LOGOUT_HTML;

    if ( cgi_info( CGI_GET, cl ) != 0 ) {
	fprintf( stderr, "%s: cgi_info broken\n", getenv( "SCRIPT_NAME" ) );
	exit( 1 );
    }

    /* clobber the cosign cookie and display logout screen */
    fputs( "Set-Cookie: cosign=logout; path=/; expires=Wednesday, 16-Apr-73 02:10:00 GMT; secure\n", stdout );

    if (( cl[ CL_LINK ].cl_data != NULL ) &&
	    ( *cl[ CL_LINK ].cl_data != '\0' )) {
	url = (char *)cl[ CL_LINK ].cl_data;
    }

    htputs( "Cache-Control: private, must-revalidate, no-cache\n"
            "Expires: Mon, 16 Apr 1973 02:10:00 GMT\n"
            "Pragma: no cache\n" );

dispage:
    subfile ( tmpl );

    exit( 0 );
}

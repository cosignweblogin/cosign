/**********	cgi.c	**********/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "cgi.h"

char *cgi_error_text[] = {
    "System memory error",
    "Syntax error in parse",
    "Invalid Request method",
    "CGI request method must be POST",
    "CGI request method must be GET",
    "Method argument out of range",
    "List argument NULL",
    "Error out of range",
};

int yyparse( void );


struct cgi_list		*yy_cl;
int			cgi_debug = 0;


    /* cgi_info is a routine that parses input from the CGI.
     *
     * the method arg allows restriction of the CGI to either CGI_POST or
     * CGI_GET.  CGI_STDIN does not check a method.  All use the same call
     * to parse stdin for CGI rval and lvals.
     *
     * return 0 on success, return cgi_errno on fail.
     *
     * setting cgi_debug to non-zero allows for verbose input processing.
     *
     * non matched or redefinded keys and their respective rvals are ignored.
     */

    int
cgi_info( int method, struct cgi_list *cl )
{
    char		*env_method;

    if ( method != CGI_STDIN ) {
	if (( env_method = getenv( "REQUEST_METHOD" )) == NULL ) {
	    return( CGI_E_REQUEST );
	}

	switch ( method ) {
	case CGI_POST:
	    if ( strcasecmp( "POST", env_method ) != 0 ) {
		return( CGI_E_POST );
	    }
	    break;

	case CGI_GET:
	    if ( strcasecmp( "GET", env_method ) != 0 ) {
		return( CGI_E_GET );
	    }
	    break;

	default:
	    return( CGI_E_METHOD );
	}
    }

    if ( cl == NULL ) {
	return( CGI_E_LIST );
    }

    yy_cl = cl;

    return( yyparse());
}


    char *
cgi_strerror( int cgi_errno )
{
    if (( cgi_errno < 1 ) || ( cgi_errno >= CGI_E_MAX )) {
	return( cgi_error_text[ CGI_E_MAX - 1 ]);
    } else {
	return( cgi_error_text[ cgi_errno - 1 ]);
    }
}


    /* prints that contents of a valid cgi_list for debugging purposes */

    void
cgi_contents( struct cgi_list *cl )
{
    int			keys;

    for ( keys = 0 ; cl->cl_key != NULL; cl++, keys++ ) {
	printf( "key:\t%s\tdata:\t", cl->cl_key );
	if ( cl->cl_data != NULL ) {
	    printf( "%s", cl->cl_data );
	} else {
	    printf( "NULL" );
	}
	printf( "\n" );
	// printf( "<BR>\n" );
    }

    printf( "There were %d keys\n", keys );
    // printf( "<BR>\n" );
}

/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <snet.h>

#include "cgi.h"
#include "conf.h"
#include "cosigncgi.h"
#include "network.h"
#include "subfile.h"

extern char	*cosign_version;
char		*cosign_host =_COSIGN_HOST;
char    	*certfile = _COSIGN_TLS_CERT;
char		*cryptofile = _COSIGN_TLS_KEY;
char		*cadir = _COSIGN_TLS_CADIR;
char		*tmpldir = _COSIGN_TMPL_DIR;
char		*cosign_conf = _COSIGN_CONF;
char		*cosign_logout_re = _COSIGN_LOGOUT_RE;

unsigned short	cosign_port;
SSL_CTX         *ctx = NULL;

struct cgi_list cl[] = {
#define CL_VERIFY	0
        { "verify", CGI_TYPE_STRING, NULL },
#define CL_URL 		1
        { "url", CGI_TYPE_STRING, NULL },
        { NULL, CGI_TYPE_UNDEF, NULL },
};

static struct subfile_list sl[] = {
#define SL_URL	0
        { 'u', SUBF_STR, _COSIGN_LOGOUT_URL },
#define SL_TITLE	1
        { 't', SUBF_STR, NULL },
#define SL_ERROR		2
        { 'r', SUBF_STR_ESC, NULL },
        { '\0', 0, NULL },
};
    static void
logout_configure()
{
    char	 *val;

    if (( val = cosign_config_get( COSIGNHOSTKEY )) != NULL ) {
        cosign_host = val;
    }
    if (( val = cosign_config_get( COSIGNLOGOUTURLKEY )) != NULL ) {
	sl[ SL_URL ].sl_data = val;
    }
    if (( val = cosign_config_get( COSIGNLOGOUTREGEXKEY )) != NULL ) {
	cosign_logout_re = val;
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
    if (( val = cosign_config_get( COSIGNTMPLDIRKEY )) != NULL ) {
        tmpldir = val;
    }
    if (( val = cosign_config_get( COSIGNPORTKEY )) != NULL ) {
        cosign_port = htons( atoi( val )); 
    } else {
	cosign_port = htons( 6663 );
    }
}

/*
 * -1: internal error
 *  0: redirect URL OK
 *  1: redirect URL doesn't match safe logout URL pattern
 */
    static int
logout_url_check( char *url )
{
    regex_t		logout_re;
    char		error[ 1024 ];
    int			rc = -1;

    /* compile regex matching valid logout redirect URLs */
    if (( rc = regcomp( &logout_re, cosign_logout_re,
			REG_EXTENDED | REG_ICASE | REG_NOSUB )) != 0 ) {
	regerror( rc, &logout_re, error, sizeof( error ));
	fprintf( stderr, "regcomp %s: %s\n", cosign_logout_re, error );

	return( -1 );
    }
    if (( rc = regexec( &logout_re, url, 0, NULL, 0 ) != 0)) {
	if ( rc != REG_NOMATCH ) {
	    regerror( rc, &logout_re, error, sizeof( error ));
	    fprintf( stderr, "regexec %s: %s\n",
			cosign_logout_re, error );
	    rc = -1;
	} else {
	    rc = 1;
	}
    } else {
	rc = 0;
    }
    regfree( &logout_re );

    return( rc );
}

    int
main( int argc, char *argv[] )
{
    CGIHANDLE		*cgi;
    char		*tmpl = VERIFY_LOGOUT;
    char		*cookie = NULL, *data, *ip_addr, *qs;
    char		*method = NULL;
    struct connlist	*head;
    char		*script;

    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    }

    if (( cosign_conf = getenv( "COSIGN_CGI_CONF" )) == NULL ) {
	cosign_conf = _COSIGN_CONF;
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	fprintf( stderr, "Couldn't read %s\n", cosign_conf );
        exit( 1 );
    }
    logout_configure();
    if ( chdir( tmpldir ) < 0 ) {
	perror( tmpldir );
	exit( 1 );
    }

    if (( ip_addr = getenv( "REMOTE_ADDR" )) == NULL ) {
        sl[ SL_TITLE ].sl_data = "Error: Server Error";
        sl[ SL_ERROR ].sl_data = "REMOTE_ADDR not set";
        tmpl = ERROR_HTML;
        subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( script = getenv( "SCRIPT_NAME" )) == NULL ) {
        sl[ SL_TITLE ].sl_data = "Error: Server Error";
        sl[ SL_ERROR ].sl_data = "SCRIPT_NAME not set";
        tmpl = ERROR_HTML;
        subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( method = getenv( "REQUEST_METHOD" )) == NULL ) {
	sl[ SL_TITLE ].sl_data = "Error: Server Error";
        sl[ SL_ERROR ].sl_data = "REQUEST_METHOD not set";
	tmpl = ERROR_HTML;
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if ( strcmp( method, "GET" ) == 0 ) {
	/* this is not a POST, display verify screen */
	if ((( qs = getenv( "QUERY_STRING" )) != NULL ) &&
		( *qs != '\0' ) &&
		( strncmp( qs, "http", 4 ) == 0 )) {
	    /* query string looks like a url, preserve it */

	    if ( logout_url_check( qs ) == 0 ) {
		/*
		 * url matches admin-defined safe redirect URL pattern.
		 * we don't really care if strdup fails here, as subfile
		 * will do the right thing and skip the URL substitution
		 * if sl_data is NULL. sl_data is not freed because we
		 * exit immediately.
		 */
		sl[ SL_URL ].sl_data = strdup( qs );
	    }
	    /* if url check fails, default logout URL will be used */
	}

	sl[ SL_TITLE ].sl_data = "Logout Requested";
	subfile ( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( cgi = cgi_init()) == NULL ){
        sl[ SL_TITLE ].sl_data = "Error: Server Error";
        sl[ SL_ERROR ].sl_data = "cgi_init failed";
        tmpl = ERROR_HTML;
        subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if ( cgi_post( cgi, cl ) != 0 ) {
	/* an actual logout must be the result of a POST, see? */
        fprintf( stderr, "%s: cgi_post failed\n", script );
        exit( 1 );
    }

    if ( cl[ CL_URL ].cl_data != NULL ) {
	/* oh the places you'll go */
        if ( strncmp( cl[ CL_URL ].cl_data, "http", 4 ) == 0 ) {
	    if ( logout_url_check( cl[ CL_URL ].cl_data ) == 0 ) {
		sl[ SL_URL ].sl_data = cl[ CL_URL ].cl_data;
	    }
	}
    }

    /*
     * Check that the 'Verify' post was sent.  If not, display the verify
     * screen again.
     */
    if ( cl[ CL_VERIFY ].cl_data == NULL ) {
	sl[ SL_TITLE ].sl_data = "Logout Requested (again?)";
	subfile ( tmpl, sl, 0 );
	exit( 0 );
    }

    /* read user's cosign cookie and LOGOUT */
    if (( data = getenv( "HTTP_COOKIE" )) != NULL ) {
        cookie = strtok( data, ";" );
        if ( cookie != NULL && strncmp( cookie, "cosign=", 7 ) != 0 ) {
            while (( cookie = strtok( NULL, ";" )) != NULL ) {
                if ( *cookie == ' ' ) ++cookie;
                if ( strncmp( cookie, "cosign=", 7 ) == 0 ) {
                    break;
                }
            }
        }
    }
    /* only the cosign= cookie and not the loop breaking info */
    if ( cookie != NULL ) (void)strtok( cookie, "/" );

    /* clobber the cosign cookie */
    fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
	    "Cache-Control: no-store, no-cache, must-revalidate\n"
	    "Cache-Control: pre-check=0, post-check=0, max-age=0\n"
	    "Pragma: no-cache\n", stdout );

    fputs( "Set-Cookie: cosign=null; path=/; expires=Wednesday, 16-Apr-73 02:10:00 GMT; secure\n", stdout );

    /* setup conn and ssl and hostlist to tell cosignd we're logged out */
    if (( head = connlist_setup( cosign_host, cosign_port )) == NULL ) {
        sl[ SL_TITLE ].sl_data = "Server Configuration Error";
        sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server.  Please quit your web browser "
		"to complete logout.";
        tmpl = ERROR_HTML;
        subfile( tmpl, sl, 0 );
        exit( 0 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx )) {
        sl[ SL_TITLE ].sl_data = "Server Configuration Error";
        sl[ SL_ERROR ].sl_data = "Failed to initialise connections to "
		"the authentication server. Please quit your browser to "
		"complete logout.";
        tmpl = ERROR_HTML;
        subfile( tmpl, sl, 0 );
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

    printf( "Location: %s\n\n", sl[ SL_URL ].sl_data );
    exit( 0 );
}

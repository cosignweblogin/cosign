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
#include <krb5.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <snet.h>
#include "cgi.h"
#include "cosigncgi.h"
#include "network.h"
#include "config.h"

#ifdef SQL_FRIEND
#include <crypt.h>
#include <mysql.h>
static	MYSQL	friend_db;
#endif

#define LOGIN_ERROR_HTML	"../templates/login_error.html"
#define ERROR_HTML	"../templates/error.html"
#define LOGIN_HTML	"../templates/login.html"
#define SERVICE_MENU	"/services/"
#define LOOP_PAGE	"https://weblogin.umich.edu/looping.html"
#define SIDEWAYS        1
#define LOOPWINDOW      30 
#define MAXREDIRECTS	10	
#define EXPIRE_TIME	86400	 /* 24 hours */

extern char	*cosign_version;
char		*cosign_host = _COSIGN_HOST;
char		*err = NULL, *ref = NULL, *service = NULL;
char		*title = "Authentication Required";
char		*keytab_path = _KEYTAB_PATH;
char		*ticket_path = _COSIGN_TICKET_CACHE;
char		*cryptofile = _COSIGN_TLS_KEY;
char		*certfile = _COSIGN_TLS_CERT;
char		*cadir = _COSIGN_TLS_CADIR;
SSL_CTX 	*ctx = NULL;

#ifdef SQL_FRIEND
char	*friend_db_name = _FRIEND_MYSQL_DB;
char	*friend_login = _FRIEND_MYSQL_LOGIN;
char	*friend_passwd = _FRIEND_MYSQL_PASSWD;
#endif

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

void	subfile( char * );
void	loop_checker( int, int, char * );

    void
loop_checker( int time, int count, char *cookie )
{
    struct timeval	tv;
    char       		new_cookie[ 255 ];
    char		*tmpl = ERROR_HTML;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	title = "Error: Loop Breaker";
	err = "Please try again later.";
	subfile( tmpl );
	exit( 0 );
    }

    /* we're past our window, all is well */
    if (( tv.tv_sec - time ) > LOOPWINDOW ) {
	time = tv.tv_sec;
	count = 1;
	if ( snprintf( new_cookie, sizeof( new_cookie ),
		"%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
	    title = "Error: Loop Breaker";
	    err = "Please try again later.";
	    subfile( tmpl );
	    exit( 0 );
	}
	printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	return;
    } else {
       /* too many redirects - break the loop and give an error */
       if ( count >= MAXREDIRECTS ) {
	    time = tv.tv_sec;
	    count = 1;
	    if ( snprintf( new_cookie, sizeof( new_cookie ),
		    "%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
		title = "Error: Loop Breaker";
		err = "Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }
	    printf( "Location:%s\n\n", LOOP_PAGE );
	    exit( 0 );
	} else {
	    /* we're still in the limit, increment and keep going */
	    count++;
	    if ( snprintf( new_cookie, sizeof( new_cookie ),
		    "%s/%d/%d", cookie, time, count) >= sizeof( new_cookie )) {
		title = "Error: Loop Breaker";
		err = "Please try again later.";
		subfile( tmpl );
		exit( 0 );
	    }
	    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
	    return;
	}
    }
}

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

	    case 'l':
                if (( cl[ CL_LOGIN ].cl_data != NULL ) &&
                        ( *cl[ CL_LOGIN ].cl_data != '\0' )) {
                    printf( "%s", cl[ CL_LOGIN ].cl_data );
                }
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


    static void
kcgi_configure()
{
    char 	*val;

    if (( val = cosign_config_get( COSIGNHOSTKEY )) != NULL ) {
	cosign_host = val;
    }
    if (( val = cosign_config_get( COSIGNKEYTABKEY )) != NULL ) {
	keytab_path = val;
    }
    if (( val = cosign_config_get( COSIGNTICKKEY )) != NULL ) {
	ticket_path = val;
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
#ifdef SQL_FRIEND
    if (( val = getConfigValue( MYSQLDBKEY )) != NULL ) {
	friend_db_name = val;
    }
    if (( val = getConfigValue( MYSQLUSERKEY )) != NULL ) {
	friend_login = val;
    }
    if (( val = getConfigValue( MYSQLPASSWDKEY )) != NULL ) {
	friend_passwd = val;
    }
#endif	
}

int
main( int argc, char *argv[] )
{
    krb5_error_code		kerror = 0;
    krb5_context		kcontext;
    krb5_principal		kprinc;
    krb5_principal		sprinc;
    krb5_get_init_creds_opt	kopts;
    krb5_creds			kcreds;
    krb5_ccache			kccache;
    krb5_keytab			keytab = 0;
    char			*realm = "no_realm";
    char			ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    int				rc, cookietime = 0, cookiecount = 0;
    char                	new_cookiebuf[ 128 ];
    char        		new_cookie[ 255 ];
    char               		tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];
    char			*data, *ip_addr;
    char			*cookie = NULL, *method, *script, *qs;
    char			*misc = NULL;
    char			*tmpl = LOGIN_HTML;
    char 			*cosign_conf = _COSIGN_CONF;
    struct timeval		tv;
    struct connlist		*head;
    unsigned short		port;

#ifdef SQL_FRIEND
    MYSQL_RES			*res;
    MYSQL_ROW			row;
    char			sql[ 225 ]; /* holds sql query + email addr */
    char			*crypted, *p;
#endif

    if ( argc == 2 && ( strncmp( argv[ 1 ], "-V", 2 ) == 0 )) {
	printf( "%s\n", cosign_version );
	exit( 0 );
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	title = "Error: But not your fault";
	err = "We were unable to parse the configuration file";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }
    kcgi_configure();

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

	(void)strtok( cookie, "/" );
	if (( misc = strtok( NULL, "/" )) != NULL ) {
	    cookietime = atoi( misc );
	}

	if (( misc = strtok( NULL, "/" )) != NULL ) {
	    cookiecount = atoi( misc );
	}
    }

    method = getenv( "REQUEST_METHOD" );
    script = getenv( "SCRIPT_NAME" );
    ip_addr = getenv( "REMOTE_ADDR" );

    /* setup conn and ssl and hostlist */
    port = htons( 6663 );
    if (( head = connlist_setup( cosign_host, port )) == NULL ) {
	title = "Error: But not your fault";
	err = "We were unable to contact the authentication server.  Please try again later.";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx ) != 0 ) {
	title = "Error: But not your fault";
	err = "Failed to initialise connections to the authentication server. Please try again later";
	tmpl = ERROR_HTML;
	subfile( tmpl );
	exit( 0 );
    }

    if ((( qs = getenv( "QUERY_STRING" )) != NULL ) && ( *qs != '\0' )) {
	if ((( service = strtok( qs, ";" )) == NULL ) ||
		( strncmp( service, "cosign-", 7 ) != 0 )) {
	    title = "Error: Unrecognized Service";
	    tmpl = ERROR_HTML;
	    err = "Unable to determine referring service from query string.";
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
	    title = "Authentication Required";
	    err = "You have not yet logged-in.";
	    goto loginscreen;
	}

	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    title = "Error: Login Screen";
	    err = "Please try again later.";
	    subfile( ERROR_HTML );
	    exit( 0 );
	}

	if (( tv.tv_sec - cookietime ) > EXPIRE_TIME ) {
	    goto loginscreen;
	}

	if (( rc = cosign_register( head, cookie, ip_addr, service )) < 0 ) {
	    if ( cosign_check( head, cookie ) < 0 ) {
		err = "You are not logged in. Please log in now.";
		goto loginscreen;
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

	loop_checker( cookietime, cookiecount, cookie );

	/* if no referrer, redirect to top of site from conf file */
	printf( "Location: %s\n\n", ref );
	exit( 0 );
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

    if ( strcmp( method, "POST" ) != 0 ) {
	if ( cosign_check( head, cookie ) < 0 ) {
	    err = "You are not logged in. Please log in now.";
	    goto loginscreen;
	}

	/* authentication successful, show service menu */
	printf( "Location: https://%s%s\n\n", cosign_host, SERVICE_MENU );
	exit( 0 );
    }

    if ( cgi_info( CGI_STDIN, cl ) != 0 ) {
	exit( SIDEWAYS );
    }

    if (( cl[ CL_REF ].cl_data != NULL ) ||
	    ( *cl[ CL_REF ].cl_data != '\0' )) {
        ref = cl[ CL_REF ].cl_data;
    }

    if (( cl[ CL_LOGIN ].cl_data == NULL ) ||
	    ( *cl[ CL_LOGIN ].cl_data == '\0' )) {
	title = "Authentication Required";
	err = "Please enter your login and password.";
        subfile ( tmpl );
	exit( 0 );
    }

    if (( cl[ CL_PASSWORD ].cl_data == NULL ) ||
	    ( *cl[ CL_PASSWORD ].cl_data == '\0' )) {
	err = "Unable to login because password is a required field.";
	title = "Missing Password";
	tmpl = LOGIN_ERROR_HTML;

        subfile ( tmpl );
	exit( 0 );
    }

    if ( strchr( cl[ CL_LOGIN ].cl_data, '@' ) != NULL ) {
#ifdef SQL_FRIEND
	if ( !mysql_real_connect( &friend_db, friend_db_name, friend_login, friend_passwd, "friend", 3306, NULL, 0 )) {
	    fprintf( stderr, mysql_error( &friend_db ));
	    err = "Unable to connect to guest account database.";
	    title = "Database Problem";

	    tmpl = ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	/* Check for sql injection prior to username query */
        for ( p = cl[ CL_LOGIN ].cl_data; *p != '\0'; p++ ) {
            if (( isalpha( *p ) != 0 ) || (isdigit( *p ) != 0 )) {
                continue;
            }

            switch ( *p ) {
                case '@':
                case '_':
                case '-':
                case '.':
                continue;
                default:
                fprintf( stderr, "invalid username: %s %s\n",
                        cl[ CL_LOGIN ].cl_data, ip_addr );

                err = "Provided login name appears to be invalid";
                title = "Invalid Input";
                tmpl = ERROR_HTML;
                subfile( tmpl );
                exit( 0 );
            }
        }
	snprintf( sql, sizeof( sql ), "SELECT account_name, passwd FROM friends WHERE account_name = '%s'", cl[ CL_LOGIN ].cl_data );

	if( mysql_real_query( &friend_db, sql, sizeof( sql ))) {
	    fprintf( stderr, mysql_error( &friend_db ));
	    err = "Unable to query guest account database.";
	    title = "Server Problem";

	    tmpl = ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if (( res = mysql_store_result( &friend_db )) == NULL ) {
	    /* was there an error?  NULL can be okay. */
	    if ( mysql_errno( &friend_db )) {
		fprintf( stderr, mysql_error( &friend_db ));
		err = "There was a problem connecting to the database.";
		title = "Database Connection Problem";

		subfile ( tmpl );
		exit( 0 );
	    }
	}

	if (( row = mysql_fetch_row( res )) == NULL ) {
	    err = "Password or Account Name incorrect.  Is [caps lock] on?";
	    title = "Authentication Required ( guest account error )";

	    subfile ( tmpl );
	    exit( 0 );
	}

	/* crypt the user's password */
	crypted = crypt( cl[ CL_PASSWORD ].cl_data, row[ 1 ] );

	if ( strcmp( crypted, row[ 1 ] ) != 0 ) {
	    mysql_free_result( res );
	    mysql_close( &friend_db );

	    /* this is a valid friend account but password failed */
	    err = "Unable to login because guest password is incorrect.";
	    title = "Authentication Required ( guest password incorrect )";

	    subfile ( tmpl );
	    exit( 0 );
	}

	mysql_free_result( res );
	mysql_close( &friend_db );

	if ( cosign_login( head, cookie, ip_addr, 
		cl[ CL_LOGIN ].cl_data, "friend", NULL ) < 0 ) {
	    fprintf( stderr, "%s: login failed\n", script ) ;

	    err = "We were unable to contact the authentication server."
		    "  Please try again later.";
	    title = "Error: Please try later";
	    tmpl = ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}
#else
	/* no @ unless we're friendly. */

	err = (char *)error_message( kerror );
	title = "Your login id may not contain an '@'";

	tmpl = LOGIN_ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
#endif
    } else {
	/* not a friend, must be kerberos */
	if (( kerror = krb5_init_context( &kcontext ))) {
	    err = (char *)error_message( kerror );
	    title = "Authentication Required ( kerberos error )";

	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if (( kerror = krb5_parse_name( kcontext, cl[ CL_LOGIN ].cl_data,
		&kprinc ))) {
	    err = (char *)error_message( kerror );
	    title = "Authentication Required ( kerberos error )";

	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	/* need to get realm out */
	if (( kerror = krb5_get_default_realm( kcontext, &realm )) != 0 ) {
	    err = (char *)error_message( kerror );
	    title = "Authentication Required ( kerberos realm error )";

	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	    err = "An unknown error occurred.";
	    title = "Authentication Required ( kerberos error )";

	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
		ticket_path, tmpkrb ) >= sizeof( krbpath )) {
	    err = "An unknown error occurred.";
	    title = "Authentication Required ( kerberos error: krbpath )";

	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if (( kerror = krb5_cc_resolve( kcontext, krbpath, &kccache )) != 0 ) {
	    err = (char *)error_message( kerror );
	    title = "Authentication Required ( kerberos error )";

	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	krb5_get_init_creds_opt_init( &kopts );
	krb5_get_init_creds_opt_set_tkt_life( &kopts, 10*60*60 );
	krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
	krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
	krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

	if (( kerror = krb5_get_init_creds_password( kcontext, &kcreds, 
		kprinc, cl[ CL_PASSWORD ].cl_data, NULL, NULL, 0, 
		NULL /*keytab */, &kopts ))) {

	    if ( kerror == KRB5KRB_AP_ERR_BAD_INTEGRITY ) {

		err = "Password incorrect.  Is [caps lock] on?";
		title = "Password Incorrect";

		tmpl = LOGIN_ERROR_HTML;
		subfile ( tmpl );
		exit( 0 );
	    } else {
		err = (char *)error_message( kerror );
		title = "Error";
		
		tmpl = LOGIN_ERROR_HTML;
		subfile ( tmpl );
		exit( 0 );
	    }
	}

	/* verify no KDC spoofing */
	if ( *keytab_path == '\0' ) {
	    if (( kerror = krb5_kt_default_name(
		    kcontext, ktbuf, MAX_KEYTAB_NAME_LEN )) != 0 ) {
		err = (char *)error_message( kerror );
		title = "Ticket Verification Error";
	    
		tmpl = LOGIN_ERROR_HTML;
		subfile ( tmpl );
		exit( 0 );

	    }
	} else {
	    if ( strlen( keytab_path ) > MAX_KEYTAB_NAME_LEN ) {
		err = "server configuration error";
		title = "Ticket Verification Error";
	
		tmpl = LOGIN_ERROR_HTML;
		subfile ( tmpl );
		exit( 0 );
	    }
	    strcpy( ktbuf, keytab_path );
	}

	if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	    err = (char *)error_message( kerror );
	    title = "KT Resolve Error";
	    
	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if (( kerror = krb5_sname_to_principal( kcontext, NULL, "cosign",
		KRB5_NT_SRV_HST, &sprinc )) != 0 ) {
	    err = (char *)error_message( kerror );
	    title = "Server Principal Error";
	    
	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if (( kerror = krb5_verify_init_creds(
		kcontext, &kcreds, sprinc, keytab, NULL, NULL )) != 0 ) {
	    err = (char *)error_message( kerror );
	    title = "Ticket Verify Error";
	    
	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    krb5_free_principal( kcontext, sprinc );
	    exit( 0 );
	}
	(void)krb5_kt_close( kcontext, keytab );
	krb5_free_principal( kcontext, sprinc );

	if (( kerror = krb5_cc_initialize( kcontext, kccache, kprinc )) != 0 ) {
	    err = (char *)error_message( kerror );
	    title = "CC Initialize Error";
	    
	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	if (( kerror = krb5_cc_store_cred( kcontext, kccache, &kcreds ))
		!= 0 ) {
	    err = (char *)error_message( kerror );
	    title = "CC Storing Error";
	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}

	krb5_free_cred_contents( kcontext, &kcreds );
	krb5_free_principal( kcontext, kprinc );
	krb5_cc_close( kcontext, kccache );
	krb5_free_context( kcontext );

	/* password has been accepted, tell cosignd */
	if ( cosign_login( head, cookie, ip_addr, 
		cl[ CL_LOGIN ].cl_data, realm, krbpath ) < 0 ) {
	    fprintf( stderr, "%s: login failed\n", script ) ;
	    err = "We were unable to contact the authentication server."
		    "  Please try again later.";
	    title = "Error: Please try later";
	    tmpl = LOGIN_ERROR_HTML;
	    subfile ( tmpl );
	    exit( 0 );
	}
    }

    if (( cl[ CL_SERVICE ].cl_data != NULL ) &&
	    ( *cl[ CL_SERVICE ].cl_data != '\0' )) {

	/* url decode here the service cookie? */

        if (( rc = cosign_register( head, cookie, ip_addr,
		cl[ CL_SERVICE ].cl_data )) < 0 ) {

	    /* this should not be possible... do it anyway? */
            if ( cosign_check( head, cookie ) < 0 ) {
                title = "Authentication Required";
                goto loginscreen;
            }

            fprintf( stderr, "%s: implicit cosign_register failed\n", script );
            title = "Error: Implicit Register Failed";
            tmpl = ERROR_HTML;
            err = "We were unable to contact the authentication server.  Please try again later.";
            subfile( tmpl );
            exit( 0 );
        }
    }

    loop_checker( cookietime, cookiecount, cookie );

    if (( ref != NULL ) && ( ref = strstr( ref, "http" )) != NULL ) {
	printf( "Location: %s\n\n", ref );
	exit( 0 );
    }

    printf( "Location: https://%s%s\n\n", cosign_host, SERVICE_MENU );
    exit( 0 );

loginscreen:
    if ( mkcookie( sizeof( new_cookiebuf ), new_cookiebuf ) != 0 ) {
	fprintf( stderr, "%s: mkcookie: failed\n", script );
	exit( SIDEWAYS );
    }

    if ( err == NULL ) {
	err = "Please type your login and password and click the Login button to continue.";
    }

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	title = "Error: Login Screen";
	err = "Please try again later.";
	subfile( ERROR_HTML );
	exit( 0 );
    }

    snprintf( new_cookie, sizeof( new_cookie ), "cosign=%s/%d",
	    new_cookiebuf, tv.tv_sec );
    printf( "Set-Cookie: %s; path=/; secure\n", new_cookie );
    subfile( tmpl );
    exit( 0 );
}

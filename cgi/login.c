/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <openssl/ssl.h>

#include <krb5.h>
#include <string.h>
#include <snet.h>

#include "cosigncgi.h"
#include "login.h"
#include "config.h"
#include "network.h"

char	*keytab_path = _KEYTAB_PATH;
char	*ticket_path = _COSIGN_TICKET_CACHE;

#define LOGIN_ERROR_HTML        "../templates/login_error.html"
#define ERROR_HTML	        "../templates/error.html"

extern char	*cosign_host, *cosign_conf, *err, *ref, *service, *title;

# ifdef SQL_FRIEND
#include <crypt.h>
#include <mysql.h>

static	MYSQL	friend_db;
char	*friend_db_name = _FRIEND_MYSQL_DB;
char	*friend_login = _FRIEND_MYSQL_LOGIN;
char	*friend_passwd = _FRIEND_MYSQL_PASSWD;
# endif  /* SQL_FRIEND */

    static void
lcgi_configure()
{
    char        *val;

    if (( val = cosign_config_get( COSIGNKEYTABKEY )) != NULL ) {
        keytab_path = val;
    }
    if (( val = cosign_config_get( COSIGNTICKKEY )) != NULL ) {
        ticket_path = val;
    }

# ifdef SQL_FRIEND
    if (( val = cosign_config_get( MYSQLDBKEY )) != NULL ) {
        friend_db_name = val;
    }
    if (( val = cosign_config_get( MYSQLUSERKEY )) != NULL ) {
        friend_login = val;
    }
    if (( val = cosign_config_get( MYSQLPASSWDKEY )) != NULL ) {
        friend_passwd = val;
    }
# endif  /* SQL_FRIEND */
}

    static void
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
                if (( login != NULL ) && ( login != '\0' )) {
                    printf( "%s", login );
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
}

# ifdef SQL_FRIEND
    int
cosign_login_mysql()
{
    MYSQL_RES		*res;
    MYSQL_ROW		row;
    char		sql[ 225 ]; /* holds sql query + email addr */
    char		*crypted, *p;
    char		*tmpl = ERROR_HTML; 

    lcgi_configure();

    if ( !mysql_real_connect( &friend_db, friend_db_name, friend_login, friend_passwd, "friend", 3306, NULL, 0 )) {
	fprintf( stderr, mysql_error( &friend_db ));
	err = "Unable to connect to guest account database.";
	title = "Database Problem";

	tmpl = ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
    }

    /* Check for sql injection prior to username query */
    for ( p = login; *p != '\0'; p++ ) {
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
	    fprintf( stderr, "invalid username: %s %s\n", login, ip_addr );

	    err = "Provided login name appears to be invalid";
	    title = "Invalid Input";
	    tmpl = ERROR_HTML;
	    subfile( tmpl );
	    exit( 0 );
	}
    }
    snprintf( sql, sizeof( sql ), "SELECT account_name, passwd FROM friends WHERE account_name = '%s'", login );

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
    crypted = crypt( passwd, row[ 1 ] );

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

    if ( cosign_login( head, cookie, ip_addr, login, "friend", NULL ) < 0 ) {
	fprintf( stderr, "cosign_login_mysql: login failed\n" ) ;

	err = "We were unable to contact the authentication server."
		"  Please try again later.";
	title = "Error: Please try later";
	tmpl = ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
    }
    return( 0 );
}
# endif /* SQL_FRIEND */

    int
cosign_login_krb5( struct connlist *head, char *login, char *passwd,
	char *ip_addr, char *cookie )
{
    krb5_error_code             kerror = 0;
    krb5_context                kcontext;
    krb5_principal              kprinc;
    krb5_principal              sprinc;
    krb5_get_init_creds_opt     kopts;
    krb5_creds                  kcreds;
    krb5_ccache                 kccache;
    krb5_keytab                 keytab = 0;
    char                        *realm = "no_realm";
    char			*tmpl = ERROR_HTML; 
    char                        ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    char                        tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];

    lcgi_configure();

    if (( kerror = krb5_init_context( &kcontext ))) {
	err = (char *)error_message( kerror );
	title = "Authentication Required ( kerberos error )";

	tmpl = LOGIN_ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
    }

    if (( kerror = krb5_parse_name( kcontext, login, &kprinc ))) {
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
	    kprinc, passwd, NULL, NULL, 0, NULL /*keytab */, &kopts ))) {

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
    if ( cosign_login( head, cookie, ip_addr, login, realm, krbpath ) < 0 ) {
	fprintf( stderr, "cosign_login_krb5: login failed\n") ;
	err = "We were unable to contact the authentication server."
		"  Please try again later.";
	title = "Error: Please try later";
	tmpl = LOGIN_ERROR_HTML;
	subfile ( tmpl );
	exit( 0 );
    }

    return( 0 );
}


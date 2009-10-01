/*
 * Copyright (c) 2005 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <errno.h>
# ifdef SQL_FRIEND
#include <crypt.h>
# endif
#include <ctype.h>

#ifdef KRB
#include <krb5.h>
#ifndef MAX_KEYTAB_NAME_LEN
#define MAX_KEYTAB_NAME_LEN 1100
#endif /* ndef MAX */
#endif /* KRB */

#include <string.h>
#include <snet.h>

#include "cosigncgi.h"
#include "login.h"
#include "conf.h"
#include "network.h"
#include "subfile.h"
#include "mkcookie.h"

extern int	errno;

#if defined( KRB ) || defined( SQL_FRIEND )

#ifdef KRB
static char	*keytab_path = _KEYTAB_PATH;
static char	*ticket_path = _COSIGN_TICKET_CACHE;
static char	*cosign_princ = NULL;
int		store_tickets = 1;
krb5_deltat	tkt_life = ( 10 * 60 * 60 );
#endif /* KRB */

extern char	*cosign_host, *cosign_conf;

extern char	*new_factors[ COSIGN_MAXFACTORS ];

static struct subfile_list sl[] = {
#define SL_LOGIN	0
        { 'l', SUBF_STR, NULL },
#define SL_TITLE	1
        { 't', SUBF_STR, NULL },
#define SL_SERVICE	2
        { 'c', SUBF_STR_ESC, NULL },
#define SL_REF		3
        { 'r', SUBF_STR_ESC, NULL },
#define SL_ERROR	4
        { 'e', SUBF_STR, NULL },
#define SL_RFACTOR		5
        { 'f', SUBF_STR_ESC, NULL },
        { '\0', 0, NULL },
};

# ifdef SQL_FRIEND
#include <mysql.h>

static MYSQL	friend_db;
static char	*friend_db_name = _FRIEND_MYSQL_DB;
static char	*friend_login = _FRIEND_MYSQL_LOGIN;
static char	*friend_passwd = _FRIEND_MYSQL_PASSWD;
# endif  /* SQL_FRIEND */

    static void
lcgi_configure()
{
    char        *val;

# ifdef KRB
    if (( val = cosign_config_get( COSIGNKEYTABKEY )) != NULL ) {
        keytab_path = val;
    }
    if (( val = cosign_config_get( COSIGNTICKKEY )) != NULL ) {
        ticket_path = val;
    }
    if (( val = cosign_config_get( COSIGNPRINCIPALKEY )) != NULL ) {
	cosign_princ = val;
    }
    if (( val = cosign_config_get( COSIGNSTORETICKETSKEY )) != NULL ) {
	if ( strcasecmp( val, "off" ) == 0 ) {
	    store_tickets = 0;
	}
    }
    if (( val = cosign_config_get( COSIGNTICKETLIFETIMEKEY )) != NULL ) {
	errno = 0;
	tkt_life = (krb5_deltat)strtol( val, NULL, 10 );
	if ( errno ) {
	    fprintf( stderr, "warning: bad %s value \"%s\", "
			"using default of 10hrs...",
			COSIGNTICKETLIFETIMEKEY, val );
	    tkt_life = ( 10 * 60 * 60 );
	}
    }
	
# endif /* KRB */

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
# endif /* SQL_FRIEND */
}

# ifdef SQL_FRIEND
    int
cosign_login_mysql( struct connlist *head, char *cosignname, char *id, 
	char *realm, char *passwd, char *ip_addr, char *cookie, 
	struct subparams *sp, char **msg )
{
    MYSQL_RES		*res;
    MYSQL_ROW		row;
    char		sql[ 225 ]; /* holds sql query + email addr */
    char		*crypted, *p;
    char		*tmpl = ERROR_HTML; 
    int			i;

    lcgi_configure();

    if ( !mysql_real_connect( &friend_db, friend_db_name, friend_login, friend_passwd, "friend", 3306, NULL, 0 )) {
	fprintf( stderr, mysql_error( &friend_db ));
	sl[ SL_ERROR ].sl_data = "Unable to connect to guest account database.";
	sl[ SL_TITLE ].sl_data = "Database Problem";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    /* Check for sql injection prior to username query */
    for ( p = id; *p != '\0'; p++ ) {
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
	    fprintf( stderr, "invalid username: %s %s\n", id, ip_addr );
	    sl[ SL_ERROR ].sl_data = "Provided login appears to be invalid";
	    sl[ SL_TITLE ].sl_data = "Invalid Input";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }
    if ( snprintf( sql, sizeof( sql ), "SELECT login, passwd"
	    " FROM friend WHERE login = '%s' AND passwd is NOT NULL",
	    id ) >= sizeof( sql )) {
	fprintf( stderr, "invalid username: %s %s\n", id, ip_addr );
	sl[ SL_ERROR ].sl_data = "Provided login appears to be invalid";
	sl[ SL_TITLE ].sl_data = "Invalid Input";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if( mysql_real_query( &friend_db, sql, strlen( sql ))) {
	fprintf( stderr, mysql_error( &friend_db ));
	sl[ SL_ERROR ].sl_data = "Unable to query guest account database.";
	sl[ SL_TITLE ].sl_data = "Server Problem";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( res = mysql_store_result( &friend_db )) == NULL ) {
	/* was there an error?  NULL can be okay. */
	if ( mysql_errno( &friend_db )) {
	    fprintf( stderr, mysql_error( &friend_db ));
	    sl[ SL_ERROR ].sl_data = "Problems connecting to the database.";
	    sl[ SL_TITLE ].sl_data = "Database Connection Problem";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }

    if (( row = mysql_fetch_row( res )) == NULL ) {
	return( COSIGN_CGI_ERROR );
    }

    /* crypt the user's password */
    crypted = crypt( passwd, row[ 1 ] );

    if ( strcmp( crypted, row[ 1 ] ) != 0 ) {
	mysql_free_result( res );
	mysql_close( &friend_db );

	/* this is a valid friend account but password failed */
	return( COSIGN_CGI_ERROR );
    }

    mysql_free_result( res );
    mysql_close( &friend_db );

    for ( i = 0; i < COSIGN_MAXFACTORS - 1; i++ ) {
	if ( new_factors[ i ] == NULL ) {
	    new_factors[ i ] = "friend";
	    new_factors[ i + 1 ] = NULL;
	    break;
	}
	if ( strcmp( new_factors[ i ], "friend" ) == 0 ) {
	    break;
	}
    }

    if ( sp->sp_reauth && sp->sp_ipchanged == 0 ) {
	return( COSIGN_CGI_OK );
    }

    if ( cosign_login( head, cookie, ip_addr, cosignname, realm, NULL ) < 0 ) {
	fprintf( stderr, "cosign_login_mysql: login failed\n" ) ;
	sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server. Please try again later.";
	sl[ SL_TITLE ].sl_data = "Error: Please try later";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }
    return( COSIGN_CGI_OK );
}
#endif /* SQL_FRIEND */

#ifdef KRB
    int
cosign_login_krb5( struct connlist *head, char *cosignname, char *id, 
	char *realm, char *passwd, char *ip_addr, char *cookie, 
	struct subparams *sp, char **msg )
{
    krb5_error_code             kerror = 0;
    krb5_context                kcontext;
    krb5_principal              kprinc;
    krb5_principal              sprinc;
    krb5_get_init_creds_opt     kopts;
    krb5_verify_init_creds_opt 	kvic_opts[ 1 ];
    krb5_creds                  kcreds;
    krb5_ccache                 kccache;
    krb5_keytab                 keytab = 0;
    char			*tmpl = ERROR_HTML; 
    char			*sprinc_name = NULL;
    char                        ktbuf[ MAX_KEYTAB_NAME_LEN + 1 ];
    char                        tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];
    int				i;

    lcgi_configure();

    if (( kerror = krb5_init_context( &kcontext ))) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Authentication Required ( kerberos error )";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    if (( kerror = krb5_parse_name( kcontext, id, &kprinc ))) {
	sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	sl[ SL_TITLE ].sl_data = "Authentication Required ( kerberos error )";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    /* need to get realm out */
    if ( realm == NULL || *realm == '\0' ) {
	if (( kerror = krb5_get_default_realm( kcontext, &realm )) != 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
 	    sl[ SL_TITLE ].sl_data = "Authentication Required "
		    "( krb realm error )";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
    	}
    }

    if ( store_tickets ) {
	if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	    sl[ SL_ERROR ].sl_data = "An unknown error occurred.";
	    sl[ SL_TITLE ].sl_data = "Authentication Required (kerberos error)";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
		ticket_path, tmpkrb ) >= sizeof( krbpath )) {
	    sl[ SL_ERROR ].sl_data = "An unknown error occurred.";
	    sl[ SL_TITLE ].sl_data = "Authentication Required (krbpath error)";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	if (( kerror = krb5_cc_resolve( kcontext, krbpath, &kccache )) != 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "Authentication Required (kerberos error)";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }

    krb5_get_init_creds_opt_init( &kopts );
    krb5_get_init_creds_opt_set_tkt_life( &kopts, tkt_life );
    krb5_get_init_creds_opt_set_renew_life( &kopts, 0 );
    krb5_get_init_creds_opt_set_forwardable( &kopts, 1 );
    krb5_get_init_creds_opt_set_proxiable( &kopts, 0 );

    if (( kerror = krb5_get_init_creds_password( kcontext, &kcreds, 
	    kprinc, passwd, NULL, NULL, 0, NULL /*keytab */, &kopts ))) {

	if (( kerror == KRB5KRB_AP_ERR_BAD_INTEGRITY ) ||
		( kerror == KRB5KDC_ERR_PREAUTH_FAILED ) ||
		( kerror == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN )) {
	    return( COSIGN_CGI_ERROR );	/* draw login or reauth page */
        } else if ( kerror == KRB5KDC_ERR_KEY_EXP ) {
	    *msg = (char *)error_message( kerror );
            return( COSIGN_CGI_PASSWORD_EXPIRED );
	} else {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "Error";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
    }

    /* verify no KDC spoofing */
    if ( *keytab_path != '\0' ) {
	if ( strlen( keytab_path ) > MAX_KEYTAB_NAME_LEN ) {
	    sl[ SL_ERROR ].sl_data = "server configuration error";
	    sl[ SL_TITLE ].sl_data = "Ticket Verification Error";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
	strcpy( ktbuf, keytab_path );

	/* from mdw */
	krb5_verify_init_creds_opt_init( kvic_opts );
	krb5_verify_init_creds_opt_set_ap_req_nofail( kvic_opts, 1 );

	if (( kerror = krb5_kt_resolve( kcontext, ktbuf, &keytab )) != 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "KT Resolve Error";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	if ( cosign_princ ) {
	    kerror = krb5_parse_name( kcontext, cosign_princ, &sprinc );
	} else {
	    kerror = krb5_sname_to_principal( kcontext, NULL, "cosign",
			KRB5_NT_SRV_HST, &sprinc );
	}
	if ( kerror != 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "Server Principal Error";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}

	if (( kerror = krb5_verify_init_creds(
		kcontext, &kcreds, sprinc, keytab, NULL, kvic_opts )) != 0 ) {
	    if ( krb5_unparse_name( kcontext, sprinc, &sprinc_name ) == 0 ) {
		fprintf( stderr, "ticket verify error for "
			 "user %s, keytab principal %s", id, sprinc_name );
		free( sprinc_name );
	    } else {
		fprintf( stderr, "ticket verify error for user %s", id );
	    }
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "Ticket Verify Error";
	    subfile( tmpl, sl, 0 );
	    krb5_free_principal( kcontext, sprinc );
	    exit( 0 );
	}
	(void)krb5_kt_close( kcontext, keytab );
	krb5_free_principal( kcontext, sprinc );
    }

    for ( i = 0; i < COSIGN_MAXFACTORS - 1; i++ ) {
	if ( new_factors[ i ] == NULL ) {
	    new_factors[ i ] = strdup( realm );
	    new_factors[ i + 1 ] = NULL;
	    break;
	}
	if ( strcmp( new_factors[ i ], realm ) == 0 ) {
	    break;
	}
    }

    if ( sp->sp_reauth && sp->sp_ipchanged == 0 ) {
	return( COSIGN_CGI_OK );
    }

    if ( store_tickets ) {
	if (( kerror = krb5_cc_initialize( kcontext, kccache, kprinc )) != 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "CC Initialize Error";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
	if (( kerror = krb5_cc_store_cred( kcontext, kccache, &kcreds ))
		!= 0 ) {
	    sl[ SL_ERROR ].sl_data = (char *)error_message( kerror );
	    sl[ SL_TITLE ].sl_data = "CC Storing Error";
	    subfile( tmpl, sl, 0 );
	    exit( 0 );
	}
	krb5_cc_close( kcontext, kccache );
    }

    krb5_free_cred_contents( kcontext, &kcreds );
    krb5_free_principal( kcontext, kprinc );
    krb5_free_context( kcontext );

    /* password has been accepted, tell cosignd */
    if ( cosign_login( head, cookie, ip_addr, cosignname, realm, 
	    ( store_tickets ? krbpath : NULL )) < 0 ) {
	fprintf( stderr, "cosign_login_krb5: login failed\n") ;
	sl[ SL_ERROR ].sl_data = "We were unable to contact the "
		"authentication server. Please try again later.";
	sl[ SL_TITLE ].sl_data = "Error: Please try later";
	subfile( tmpl, sl, 0 );
	exit( 0 );
    }

    return( COSIGN_CGI_OK );
}

#endif /* KRB */
#endif /* KRB || SQL_FRIEND */

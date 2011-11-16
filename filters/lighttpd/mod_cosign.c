#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/times.h>

#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#ifdef KRB
#ifdef GSS
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif /* GSS */
#endif /* KRB */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pcre.h>

#include <snet.h>

/* lighttpd headers */
#include "base.h"
#include "log.h"
#include "buffer.h"
#include "response.h"

#include "plugin.h"

/* cosign headers */
#include "logging.h"

#include "argcargv.h"
#include "sparse.h"
#include "mkcookie.h"
#include "cosignpaths.h"
#include "cosign.h"

extern int			errno;
extern int			h_errno;

/* cosign module for lighttpd. http://weblogin.org/ */

/* plugin config for all request/connections */

typedef struct {
    buffer			*host;
    buffer			*service;
    buffer			*siteentry;
    array			*reqf;		/* equiv. to reqfv + reqfc */
    buffer			*suffix;
    unsigned short		fake;
    unsigned short		public;
    buffer			*redirect;
    buffer			*posterror;
    buffer			*handleruri;	/* no SetHandler. fake it. */
    buffer			*validref;
    pcre			*validpcre;	/* instead of (ap_)regex_t */
    buffer			*referr;
    unsigned short		port;
    unsigned short		protect;
    int				checkip;
    array			*crypto;	/* holds cert, key, cadir */
    buffer			*filterdb;
    int				hashlen;
    buffer			*proxydb;
    buffer			*tkt_prefix;
    unsigned short		http;
    unsigned short		noappendport;
    unsigned short		proxy;
    int				expiretime;
#ifdef KRB
    unsigned short		krbtkt;		
#ifdef GSS
    unsigned short		gss;
#endif /* GSS */
#endif /* KRB */
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	/*
	 * config passed into functions common to apache,
	 * apache2 & lighttpd modules.
	 */
	cosign_host_config	*pd_cfg;

	plugin_config		**config_storage;

	plugin_config		conf;
} plugin_data;

static int	cosign_set_crypto( server *, plugin_data *, array * );
static int	cosign_set_host( server *, plugin_data *, buffer * );
static int	cosign_set_valid_reference( server *, plugin_config * );

/* init the plugin data */
INIT_FUNC( mod_cosign_init )
{
    plugin_data			*p;

    if (( p = calloc( 1, sizeof( *p ))) != NULL ) {
	/*
	 * this data structure is used by the functions common to all the web
	 * server cosign modules. its configuration-related members are
	 * populated in mod_cosign_patch_connection(). other members, like
	 * the connlist and the SSL ctx, are allocated elsewhere.
	 *
	 * the use of assert() is in line with other lighttpd allocation
	 * conventions (cf. buffer_init()).
	 */
	p->pd_cfg = calloc( 1, sizeof( cosign_host_config ));
	assert( p->pd_cfg );
    }

    return( p );
}

/* detroy the plugin data */
FREE_FUNC( mod_cosign_free )
{
    plugin_data			*p = p_d;
    unsigned int		i;

    if ( !p ) {
	return( HANDLER_GO_ON );
    }

    if ( p->config_storage ) {
	for ( i = 0; i < srv->config_context->used; i++ ) {
	    plugin_config 	*s = p->config_storage[i];

	    if (( s = p->config_storage[ i ] ) == NULL ) {
		continue;
	    }

	    buffer_free( s->host );
	    buffer_free( s->service );
	    buffer_free( s->siteentry );
	    array_free( s->reqf );
	    buffer_free( s->suffix );
	    buffer_free( s->redirect );
	    buffer_free( s->posterror );
	    buffer_free( s->handleruri );
	    buffer_free( s->validref );
	    if ( s->validpcre != NULL ) {
		pcre_free( s->validpcre );
	    }
	    buffer_free( s->referr );
	    array_free( s->crypto );
	    buffer_free( s->filterdb );
	    buffer_free( s->proxydb );
	    buffer_free( s->tkt_prefix );

	    free( p->config_storage[ i ] );
	}
	free( p->config_storage );
    }

    /*
     * here we'll need to free the SSL ctx, destroy the connlist, free the
     * reqfv, and free the struct itself. all the other members point to
     * internal lighttpd data structures, which are destroyed above.
     */
    if ( p->pd_cfg->reqfv != NULL ) {
	free( p->pd_cfg->reqfv );
	p->pd_cfg->reqfv = NULL;
    }
    if ( p->pd_cfg->ctx != NULL ) {
	SSL_CTX_free( p->pd_cfg->ctx );
	p->pd_cfg->ctx = NULL;
    }
    if ( p->pd_cfg->cl != NULL ) {
	struct connlist		**cur, **tmp;

	teardown_conn( p->pd_cfg->cl, srv );
	for ( cur = p->pd_cfg->cl; *cur != NULL; cur = tmp ) {
	    tmp = &(*cur)->conn_next;

	    free( *cur );
	    *cur = NULL;
	}
	free( p->pd_cfg->cl );
	p->pd_cfg->cl = NULL;
    }
    if ( p->pd_cfg != NULL ) {
	free( p->pd_cfg );
	p->pd_cfg = NULL;
    }

    free( p );

    return( HANDLER_GO_ON );
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC( mod_cosign_set_defaults )
{
    plugin_data		*p = p_d;
    size_t		i = 0;

    config_values_t cv[] = {
#define	LT_COSIGN_POST_ERROR_REDIRECT		0
	    { "cosign.post-error-redirect", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_SERVICE			1
	    { "cosign.service", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_PROTECTED			2
	    { "cosign.protected", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_REDIRECT			3
	    { "cosign.redirect", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_VALIDATION_HANDLER_URI	4
	    { "cosign.validation-handler-uri", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_VALID_REFERENCE		5
	    { "cosign.valid-reference", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_VALIDATION_ERROR_REDIRECT	6
	    { "cosign.validation-error-redirect", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_PORT				7
	    { "cosign.port", NULL,
		    T_CONFIG_SHORT, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_HOSTNAME			8
	    { "cosign.hostname", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_FILTER_DB			9
	    { "cosign.filter-db", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_TICKET_PREFIX			10
	    { "cosign.ticket-prefix", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_CHECK_IP			11
	    { "cosign.check-ip", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_REQUIRE_FACTOR		12
	    { "cosign.require-factor", NULL,
		    T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_FACTOR_SUFFIX			13
	    { "cosign.factor-suffix", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_FACTOR_SUFFIX_IGNORE		14
	    { "cosign.factor-suffix-ignore", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_ALLOW_PUBLIC_ACCESS		15
	    { "cosign.allow-public-access", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_HTTP_ONLY			16
	    { "cosign.http-only", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_NO_APPEND_REDIRECT_PORT	17
	    { "cosign.no-append-redirect-port", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_CRYPTO			18
	    { "cosign.crypto", NULL,
		    T_CONFIG_ARRAY, T_CONFIG_SCOPE_SERVER },
#define LT_COSIGN_GET_PROXY_COOKIES		19
	    { "cosign.get-proxy-cookies", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#define LT_COSIGN_COOKIE_EXPIRE_TIME		20
	    { "cosign.cookie-expire-time", NULL,
		    T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
#ifdef KRB
#define LT_COSIGN_GET_KERBEROS_TICKETS		21
	    { "cosign.get-kerberos-tickets", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#ifdef GSS
#define LT_COSIGN_KERBEROS_SETUP_GSS		22
	    { "cosign.kerberos-setup-gss", NULL,
		    T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
#endif /* GSS */
#endif /* KRB */
	    { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if ( p == NULL ) {
	return( HANDLER_ERROR );
    }

    p->config_storage = calloc( 1, srv->config_context->used *
				   sizeof( specific_config * ));
    if ( p->config_storage == NULL ) {
	return( HANDLER_ERROR );
    }

    for ( i = 0; i < srv->config_context->used; i++ ) {
	plugin_config	*s;

	if (( s = calloc( 1, sizeof( plugin_config ))) == NULL ) {
	    return( HANDLER_ERROR );
	}
	
#define _FILTER_DB		"/var/cosign/filter"
#define _PROXY_DB		"/var/cosign/proxy"
#define _COSIGN_TICKET_CACHE	"/ticket"
	s->host = buffer_init();
	s->service = buffer_init();
	s->siteentry = buffer_init();
	s->reqf = array_init();
	s->suffix = buffer_init();
	s->fake = 0;
	s->public = 0;
	s->redirect = buffer_init();
	s->posterror = buffer_init();
	s->handleruri = buffer_init();
	s->validref = buffer_init();
	s->validpcre = NULL;
	s->referr = buffer_init();
	s->port = 0;
	s->protect = 0;
	s->checkip = IPCHECK_NEVER;
	s->crypto = array_init();
	s->filterdb = buffer_init_string( _FILTER_DB );
	s->hashlen = 0;
	s->proxydb = buffer_init_string( _PROXY_DB );
	s->tkt_prefix = buffer_init_string( _COSIGN_TICKET_CACHE );
	s->http = 0;
	s->noappendport = 0;
	s->proxy = 0;
	s->expiretime = 86400;	/* 24 hours */
#ifdef KRB
	s->krbtkt = 0;
#ifdef GSS
	s->gss = 0;
#endif /* GSS */
#endif /* KRB */

	cv[ LT_COSIGN_POST_ERROR_REDIRECT ].destination = s->posterror;
	cv[ LT_COSIGN_SERVICE ].destination = s->service;
	cv[ LT_COSIGN_PROTECTED ].destination = &s->protect;
	cv[ LT_COSIGN_REDIRECT ].destination = s->redirect;
	cv[ LT_COSIGN_VALIDATION_HANDLER_URI ].destination = s->handleruri;
	cv[ LT_COSIGN_VALID_REFERENCE ].destination = s->validref;
	cv[ LT_COSIGN_VALIDATION_ERROR_REDIRECT ].destination = s->referr;
	cv[ LT_COSIGN_PORT ].destination = &s->port;
	cv[ LT_COSIGN_HOSTNAME ].destination = s->host;
	cv[ LT_COSIGN_FILTER_DB ].destination = s->filterdb;
	cv[ LT_COSIGN_TICKET_PREFIX ].destination = s->tkt_prefix;
	cv[ LT_COSIGN_CHECK_IP ].destination = &s->checkip;
	cv[ LT_COSIGN_REQUIRE_FACTOR ].destination = s->reqf;
	cv[ LT_COSIGN_FACTOR_SUFFIX ].destination = s->suffix;
	cv[ LT_COSIGN_FACTOR_SUFFIX_IGNORE ].destination = &s->fake;
	cv[ LT_COSIGN_ALLOW_PUBLIC_ACCESS ].destination = &s->public;
	cv[ LT_COSIGN_HTTP_ONLY ].destination = &s->http;
	cv[ LT_COSIGN_NO_APPEND_REDIRECT_PORT ].destination =
						&s->noappendport;
	cv[ LT_COSIGN_CRYPTO ].destination = s->crypto;
	cv[ LT_COSIGN_GET_PROXY_COOKIES ].destination = &s->proxy;
	cv[ LT_COSIGN_COOKIE_EXPIRE_TIME ].destination = &s->expiretime;
#ifdef KRB
	cv[ LT_COSIGN_GET_KERBEROS_TICKETS ].destination = &s->krbtkt;
#ifdef GSS
	cv[ LT_COSIGN_KERBEROS_SETUP_GSS ].destination = &s->gss;
#endif /* GSS */
#endif /* KRB */

	p->config_storage[ i ] = s;

	if ( config_insert_values_global( srv,
		((data_config *)srv->config_context->data[ i ] )->value,
		cv ) != 0 ) {
	    return( HANDLER_ERROR );
	}

	if ( !buffer_is_empty( s->host )) {
	    if ( cosign_set_host( srv, p, s->host ) != 0 ) {
		return( HANDLER_ERROR );
	    }
	}
	if ( s->crypto->used > 0 ) {
	    if ( cosign_set_crypto( srv, p, s->crypto ) != 0 ) {
		return( HANDLER_ERROR );
	    }
	}
	if ( cosign_set_valid_reference( srv, s ) != 0 ) {
	    return( HANDLER_ERROR );
	}
    }

    return( HANDLER_GO_ON );
}

    static int
cosign_set_valid_reference( server *srv, plugin_config *cfg )
{
    const char		*error;
    int			rc;

    if ( buffer_is_empty( cfg->validref )) {
	return( 0 );
    }

    if (( cfg->validpcre = pcre_compile( cfg->validref->ptr, 0,
					&error, &rc, NULL )) == NULL ) {
	log_error_write( srv, __FILE__, __LINE__, "sbss",
		"mod_cosign: cosign_set_valid_reference: "
		"pcre_compile", cfg->validref, ":", error );
	return( -1 );
    }

    return( 0 );
}

    static int
cosign_set_host( server *srv, plugin_data *p_d, buffer *host )
{
    plugin_data		*p = p_d;
    struct hostent	*he;
    struct connlist	*new, **cur;
    int			i;

    if ( p->pd_cfg->cl != NULL ) {
	/* already configured. */
	return( 0 );
    }

    if ( buffer_is_empty( host )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		"mod_cosign: cosign.hostname is not set." );
	return( -1 );
    }
    
    if (( p->pd_cfg->cl = calloc( 1, sizeof( struct connlist * ))) == NULL ) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		"mod_cosign: cosign_set_host: calloc failed" );
	return( -1 );
    }
    if (( he = gethostbyname( host->ptr )) == NULL ) {
	log_error_write( srv, __FILE__, __LINE__, "sbss",
		"mod_cosign: cosign_set_host: gethostbyname", host, ":",
		hstrerror( h_errno ));
	return( -1 );
    }

    cur = p->pd_cfg->cl;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	new = calloc( 1, sizeof( struct connlist ));
	new->conn_sin.sin_family = AF_INET;
	if ( p->conf.port == 0 ) {
	    new->conn_sin.sin_port = htons( 6663 );
	} else {
	    new->conn_sin.sin_port = htons( p->conf.port );
	}
	memcpy( &new->conn_sin.sin_addr.s_addr,
		he->h_addr_list[ i ], (unsigned int)he->h_length );
	new->conn_sn = NULL;
	*cur = new;
	cur = &new->conn_next;
    }
    *cur = NULL;

    return( 0 );
}

    static int
cosign_set_crypto( server *srv, plugin_data *p_d, array *crypto )
{
    plugin_data		*p = p_d;
    data_string		*cert = NULL;
    data_string		*key = NULL;
    data_string		*cadir = NULL;
    struct stat		st;

    if ( p->pd_cfg->ctx != NULL ) {
	/* already configured */
	return( 0 );
    }

    cert = (data_string *)array_get_element( crypto, "cert" );
    key = (data_string *)array_get_element( crypto, "key" );
    cadir = (data_string *)array_get_element( crypto, "cadir" );

    if ( crypto->used != 3 || cert == NULL || key == NULL || cadir == NULL ) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		"mod_cosign: cosign.crypto requires \"cert\", "
		"\"key\" and \"cadir\" entries." );
	return( -1 );
    }

    if ( stat( cadir->value->ptr, &st ) != 0 ) {
	log_error_write( srv, __FILE__, __LINE__, "sbs",
		"mod_cosign: stat CApath ", cadir->value, strerror( errno ));
	return( -1 );
    }

    if ( access( cert->value->ptr, R_OK ) != 0 ) {
	log_error_write( srv, __FILE__, __LINE__, "sb",
		"mod_cosign: read cert", cert->value, "failed." );
	return( -1 );
    }
    if ( access( key->value->ptr, R_OK ) != 0 ) {
	log_error_write( srv, __FILE__, __LINE__, "sb",
		"mod_cosign: read key", key->value, "failed." );
	return( -1 );
    }
    if ( S_ISDIR( st.st_mode )) {
	if ( access( cadir->value->ptr, R_OK | X_OK ) != 0 ) {
	    log_error_write( srv, __FILE__, __LINE__, "sb",
		    "mod_cosign: read CAdir ", cadir->value, "failed." );
	    return( -1 );
	}
    } else if ( access( cadir->value->ptr, R_OK ) != 0 ) {
	log_error_write( srv, __FILE__, __LINE__, "sb",
		"mod_cosign: read CAfile ", cadir->value, "failed." );
	return( -1 );
    }

    SSL_load_error_strings();
    SSL_library_init();
    if (( p->pd_cfg->ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		"mod_cosign: SSL_CTX_new:",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }
    if ( SSL_CTX_use_PrivateKey_file( p->pd_cfg->ctx, key->value->ptr,
		SSL_FILETYPE_PEM ) != 1 ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		"mod_cosign: SSL_CTX_use_PrivateKey_file:",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( p->pd_cfg->ctx,
		cert->value->ptr ) != 1 ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		"mod_cosign: SSL_CTX_use_certificate_chain_file:",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }
    if ( SSL_CTX_check_private_key( p->pd_cfg->ctx ) != 1 ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		"mod_cosign: SSL_CTX_check_private_key:",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }
    if ( S_ISDIR( st.st_mode )) {
	if ( SSL_CTX_load_verify_locations( p->pd_cfg->ctx, NULL,
		    cadir->value->ptr  ) != 1 ) {
	    log_error_write( srv, __FILE__, __LINE__, "ss",
		    "mod_cosign: CAdir SSL_CTX_load_verify_locations:",
		    ERR_error_string( ERR_get_error(), NULL ));
	    return( -1 );
	}
    } else if ( SSL_CTX_load_verify_locations( p->pd_cfg->ctx,
		cadir->value->ptr, NULL ) != 1 ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		"mod_cosign: CAfile SSL_CTX_load_verify_locations:",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }
    SSL_CTX_set_verify( p->pd_cfg->ctx,
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL );
    
    return( 0 );
}

#define PATCH(x) \
	p->conf.x = s->x;
#define PATCH_CFG_FLAG(x)						\
	p->pd_cfg->x = s->x;
#define PATCH_CFG_INT(x)						\
	p->pd_cfg->x = s->x;
#define PATCH_CFG_PTR(x)						\
	/* x is a lighttpd buffer. */					\
	if ( s->x->used > 0 ) {						\
	    p->pd_cfg->x = s->x->ptr;					\
	} else {							\
	    p->pd_cfg->x = NULL;					\
	}
#define PATCH_CFG_VECTOR(x, y ,z)					\
	/* x: an unkeyed lighttpd array. y: a char **. z: an int. */	\
	if (( u = s->x->used ) > 0 ) {					\
	    if ( u > (size_t)p->pd_cfg->z ) {				\
		if (( p->pd_cfg->y = realloc( p->pd_cfg->y,		\
						sizeof(char *) +	\
						(u + 1))) == NULL ) {	\
		    abort();						\
		}							\
	    }								\
	    p->pd_cfg->z = (int)u;					\
	    for ( u = 0; u < (size_t)p->pd_cfg->z; u++ ) {		\
		data_string	*ds = (data_string *)s->x->data[ u ];	\
									\
		if ( ds && ds->value && ds->value->ptr ) {		\
		    p->pd_cfg->y[ u ] = ds->value->ptr;			\
		}							\
	    }								\
	    p->pd_cfg->y[ u ] = NULL;					\
	}
#define PATCH_CFG_KEYVAL(x, y, z)					\
	/* x: a keyed lighttpd array. y: key we want. z: char *. */	\
    {									\
	data_string		*ds;					\
	ds = (data_string *)array_get_element( s->x, y );		\
	if ( ds != NULL ) {						\
	    p->pd_cfg->z = ds->value->ptr; 				\
	} else {							\
	    p->pd_cfg->z = NULL;					\
	}								\
    }
	
    static int
mod_cosign_patch_connection( server *srv, connection *con,
		plugin_data *p )
{
    size_t			i, j, u;
    plugin_config		*s = p->config_storage[ 0 ];

    /* lighttpd data     |   	cosign common data */
    PATCH( posterror );		PATCH_CFG_PTR( posterror );
    PATCH( service );		PATCH_CFG_PTR( service );
    PATCH( protect );		PATCH_CFG_FLAG( protect );
    PATCH( redirect );		PATCH_CFG_PTR( redirect );
    PATCH( handleruri )	
    PATCH( validref );		PATCH_CFG_PTR( validref );
    PATCH( validpcre );
    PATCH( referr );		PATCH_CFG_PTR( referr );
    PATCH( port );		PATCH_CFG_INT( port );
    PATCH( host );		PATCH_CFG_PTR( host );
    PATCH( filterdb );		PATCH_CFG_PTR( filterdb );
    PATCH( tkt_prefix );	PATCH_CFG_PTR( tkt_prefix );
    PATCH( checkip );		PATCH_CFG_INT( checkip );
    PATCH( reqf );		PATCH_CFG_VECTOR( reqf, reqfv, reqfc );
    PATCH( suffix );		PATCH_CFG_PTR( suffix );
    PATCH( fake );		PATCH_CFG_FLAG( fake );
    PATCH( public );		PATCH_CFG_FLAG( public );
    PATCH( http );		PATCH_CFG_FLAG( http );
    PATCH( noappendport );	PATCH_CFG_FLAG( noappendport );
    PATCH( crypto );		PATCH_CFG_KEYVAL( crypto, "cert", cert );
				PATCH_CFG_KEYVAL( crypto, "key", key );
				PATCH_CFG_KEYVAL( crypto, "cadir", cadir );
    PATCH( proxy );		PATCH_CFG_FLAG( proxy );
    PATCH( expiretime );	PATCH_CFG_INT( expiretime );
#ifdef KRB
    PATCH( krbtkt );		PATCH_CFG_FLAG( krbtkt );
#ifdef GSS
    PATCH( gss );		PATCH_CFG_FLAG( gss );
#endif /* GSS */
#endif /* KRB */

    /* skip the first, the global context */
    for ( i = 1; i < srv->config_context->used; i++ ) {
	data_config	*dc = (data_config *)srv->config_context->data[ i ];

	s = p->config_storage[ i ];

	/* condition didn't match */
	if ( !config_check_cond( srv, con, dc )) {
	    continue;
	}

	/* merge config */
	for ( j = 0; j < dc->value->used; j++ ) {
	    data_unset	*du = dc->value->data[ j ];

#define KEY_MATCH(x, y)	buffer_is_equal_string((x), CONST_STR_LEN((y)))

	    if ( KEY_MATCH( du->key, "cosign.post-error-redirect" )) {
		PATCH( posterror );	PATCH_CFG_PTR( posterror );
	    } else if ( KEY_MATCH( du->key, "cosign.service" )) {
		PATCH( service );	PATCH_CFG_PTR( service );
	    } else if ( KEY_MATCH( du->key, "cosign.protected" )) {
		PATCH( protect );	PATCH_CFG_FLAG( protect );
	    } else if ( KEY_MATCH( du->key, "cosign.redirect" )) {
		PATCH( redirect );	PATCH_CFG_PTR( redirect );
	    } else if ( KEY_MATCH( du->key, "cosign.validation-handler-uri" )) {
		PATCH( handleruri );
	    } else if ( KEY_MATCH( du->key, "cosign.valid-reference" )) {
		PATCH( validref );	PATCH_CFG_PTR( validref );
		PATCH( validpcre );
	    } else if (KEY_MATCH(du->key, "cosign.validation-error-redirect")) {
		PATCH( referr );	PATCH_CFG_PTR( referr );
	    } else if ( KEY_MATCH( du->key, "cosign.port" )) {
		PATCH( port );		PATCH_CFG_INT( port );
	    } else if ( KEY_MATCH( du->key, "cosign.hostname" )) {
		PATCH( host );		PATCH_CFG_PTR( host );
	    } else if ( KEY_MATCH( du->key, "cosign.filter-db" )) {
		PATCH( filterdb );	PATCH_CFG_PTR( filterdb );
	    } else if ( KEY_MATCH( du->key, "cosign.ticket-prefix" )) {
		PATCH( tkt_prefix );	PATCH_CFG_PTR( tkt_prefix );
	    } else if ( KEY_MATCH( du->key, "cosign.check-ip" )) {
		PATCH( checkip );	PATCH_CFG_INT( checkip );
	    } else if ( KEY_MATCH( du->key, "cosign.require-factor" )) {
		PATCH( reqf );		PATCH_CFG_VECTOR( reqf, reqfv, reqfc );
	    } else if ( KEY_MATCH( du->key, "cosign.factor-suffix" )) {
		PATCH( suffix );	PATCH_CFG_PTR( suffix );
	    } else if ( KEY_MATCH( du->key, "cosign.factor-suffix-ignore" )) {
		PATCH( fake );		PATCH_CFG_FLAG( fake );
	    } else if ( KEY_MATCH( du->key, "cosign.allow-public-access" )) {
		PATCH( public );	PATCH_CFG_FLAG( public );
	    } else if ( KEY_MATCH( du->key, "cosign.http-only" )) {
		PATCH( http );		PATCH_CFG_FLAG( http );
	    } else if ( KEY_MATCH( du->key, "cosign.no-append-redirect-port")) {
		PATCH( noappendport );	PATCH_CFG_FLAG( noappendport );
	    } else if ( KEY_MATCH( du->key, "cosign.crypto" )) {
		PATCH( crypto );	PATCH_CFG_KEYVAL(crypto, "cert", cert);
					PATCH_CFG_KEYVAL(crypto, "key", key);
					PATCH_CFG_KEYVAL(crypto, "cadir",cadir);
	    } else if ( KEY_MATCH( du->key, "cosign.get-proxy-cookies" )) {
		PATCH( proxy );		PATCH_CFG_FLAG( proxy );
	    } else if ( KEY_MATCH( du->key, "cosign.cookie-expire-time" )) {
		PATCH( expiretime );	PATCH_CFG_INT( expiretime );
#ifdef KRB
	    } else if ( KEY_MATCH( du->key, "cosign.get-kerberos-tickets" )) {
		PATCH( krbtkt );	PATCH_CFG_FLAG( krbtkt );
#ifdef GSS
	    } else if ( KEY_MATCH( du->key, "cosign.kerberos-setup-gss" )) {
		PATCH( gss );		PATCH_CFG_FLAG( gss );
#endif /* GSS */
#endif /* KRB */
	    }
	}
#undef KEY_MATCH
    }

    return( 0 );
}
#undef PATCH
#undef PATCH_CFG_FLAG
#undef PATCH_CFG_INT
#undef PATCH_CFG_PTR
#undef PATCH_CFG_VECTOR
#undef PATCH_CFG_KEYVAL

    static int
cosign_redirect( server *srv, connection *con, plugin_data *p_d )
{
    plugin_data		*p = p_d;
    request		r = con->request;
    unsigned short	port;
    unsigned int	i;
    char		pbuf[ 10 ];	/* room for :port_number */
    char		*tmp;

    data_string		*ds = NULL;
    buffer		*ref = NULL;
    buffer		*reqfact = NULL;
    buffer		*dest;

    if ( r.http_method == HTTP_METHOD_POST ) {
	response_header_insert( srv, con, CONST_STR_LEN( "Location" ),
					CONST_BUF_LEN( p->conf.posterror ));
	con->http_status = 302;		/* "moved temporarily" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( 0 );
    }

    if ( p->conf.siteentry != NULL && buffer_caseless_compare(
					CONST_BUF_LEN( p->conf.siteentry ),
					CONST_STR_LEN( "none" )) != 0 ) {
	ref = buffer_init_buffer( p->conf.siteentry );
    } else {
	if ( p->conf.http ) {
	    ref = buffer_init_string( "http://" );
	} else {
	    ref = buffer_init_string( "https://" );
	}

	/*
	 * weird. con->server_name isn't always set. mod_mysql_vhost falls
	 * back to copying con->uri.authority into con->server_name.
	 * mod_cgi falls back to calling inet_ntoX on the connection's
	 * server_socket->addr.{plain,ipv4}.sin_addr if con->server_name
	 * is empty. wtf?
	 *
	 * in the (evidently likely) event that con->server_name is empty,
	 * just copy the uri authority, which contains any port number.
	 */
	if ( con->server_name == NULL || buffer_is_empty( con->server_name )) {
	    buffer_append_string_buffer( ref, con->uri.authority );
	    if ( p->conf.noappendport ) {
		if (( tmp = strrchr( con->uri.authority->ptr, ':' )) != NULL ) {
		    /* XXX IPv6 addresses? */
		    con->uri.authority->used -= strlen( tmp );
		    *tmp = '\0';
		}
	    }
	} else {
	    server_socket	*ss = (server_socket *)con->srv_socket;

	    buffer_append_string_buffer( ref, con->server_name );

	    port = ntohs( ss->addr.ipv4.sin_port );
	    if ( port != ( p->conf.http ? 80 : 443 )
		    && !p->conf.noappendport ) {
		snprintf( pbuf, sizeof( pbuf ) - 1, ":%d", port );
		buffer_append_string( ref, pbuf );
	    }
	}

	buffer_append_string_buffer( ref, con->request.uri );
    }

    if ( p->conf.reqf->used > 0 ) {
	/* append factors to query string. */
	reqfact = buffer_init_string( "factors=" );
	
	ds = (data_string *)p->conf.reqf->data[ 0 ];
	buffer_append_string_buffer( reqfact, ds->value );

	for ( i = 1; i < p->conf.reqf->used; i++ ) {
	    buffer_append_string_len( reqfact, CONST_STR_LEN( "," ));
	    ds = (data_string *)p->conf.reqf->data[ i ];
	    buffer_append_string_buffer( reqfact, ds->value );
	}
    }

    /* build destination URL. */
    dest = buffer_init_buffer( p->conf.redirect );
    buffer_append_string_len( dest, CONST_STR_LEN( "?" ));
    if ( reqfact != NULL ) {
	buffer_append_string_buffer( dest, reqfact );
	buffer_append_string_len( dest, CONST_STR_LEN( "&" ));
	buffer_free( reqfact );
    }
    buffer_append_string_buffer( dest, p->conf.service );
    buffer_append_string_len( dest, CONST_STR_LEN( "&" ));
    buffer_append_string_buffer( dest, ref );
    buffer_free( ref );
    
    response_header_insert( srv, con, CONST_STR_LEN( "Location" ),
					CONST_BUF_LEN( dest ));
    con->http_status = 302;
    con->mode = DIRECT;
    con->file_finished = 1;

    buffer_free( dest );

    return( 0 );
}

    static int
cosign_handler( server *srv, connection *con, plugin_data *p_d )
{
    plugin_data		*p = p_d;
    buffer		*cookie = NULL;
    buffer		*dest = NULL;

    struct timeval	now;
    struct sinfo	si;
    int			rc;
    int			cv;
    int			ovec[ 3 ];	/* pcre ovector, space for 1 match. */
    char		*qs = NULL;
    char		*rekey = NULL;
    char		*pt;
    char		*ipaddr;
    char		timebuf[ 21 ]; /* enough to hold a string
					  representation of 64-bit ULONG_MAX. */

    if ( !buffer_is_equal( con->uri.path, p->conf.handleruri )) {
	return( HANDLER_GO_ON );
    }

    if ( con->request.http_method != HTTP_METHOD_GET &&
		con->request.http_method != HTTP_METHOD_HEAD ) {
	response_header_insert( srv, con, CONST_STR_LEN( "Location" ),
					CONST_BUF_LEN( p->conf.posterror ));
	con->http_status = 405;		/* "method not allowed" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( HANDLER_FINISHED );
    }

    if ( p->conf.validref == NULL || buffer_is_empty( p->conf.validref )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
			"mod_cosign: cosign.valid-reference not set." );
	con->http_status = 503;		/* "service unavailable" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( HANDLER_FINISHED );
    }
    if ( p->conf.referr == NULL || buffer_is_empty( p->conf.referr )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		    "mod_cosign: cosign.validation-error-redirect not set." );
	con->http_status = 503;		/* "service unavailable" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( HANDLER_FINISHED );
    }

    /* get cookie and destination from query string. */
    if ( con->uri.query == NULL || buffer_is_empty( con->uri.query )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		    "mod_cosign: no query string passed to handler." );
	con->http_status = 403;		/* "forbidden" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( HANDLER_FINISHED );
    }
    qs = con->uri.query->ptr;

    if ( strncasecmp( qs, "cosign-", strlen( "cosign-" )) != 0 ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		    "mod_cosign: invalid service in query string", qs );
	goto validation_failed;
    }
    if (( pt = strchr( qs, '&' )) == NULL ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		    "mod_cosign: malformed query string: ", qs );
	goto validation_failed;
    }
    *pt = '\0';
    cookie = buffer_init_string( qs );
    *pt = '&';

    pt++;
    if ( pt == NULL || *pt == '\0' ) {
	log_error_write( srv, __FILE__, __LINE__, "ss",
		    "mod_cosign: malformed query string: ", qs );
	goto validation_failed;
    }
    dest = buffer_init_string( pt );

    if (( rc = pcre_exec( p->conf.validpcre, NULL, dest->ptr, dest->used,
				0, PCRE_ANCHORED,
				ovec, sizeof( ovec ))) < 0 ) {
	if ( rc != PCRE_ERROR_NOMATCH ) {
	    log_error_write( srv, __FILE__, __LINE__, "sbsd",
		    "mod_cosign: pcre_exec", p->conf.validref,
		    "returned error", rc );

	    con->http_status = 500;		/* "internal server error" */
	    con->mode = DIRECT;
	    con->file_finished = 1;

	    return( HANDLER_FINISHED );
	}

	log_error_write( srv, __FILE__, __LINE__, "sb",
		    "mod_cosign: invalid destination:", dest );
	goto validation_failed;
    }
    if ( rc == 0 ) {
	/*
	 * ovector not big enough to hold captured substrings.
	 * we're not using captured substrings, so consider it
	 * an error.
	 */
	log_error_write( srv, __FILE__, __LINE__, "sbs",
		    "mod_cosign: cosign.valid-reference pattern",
		    p->conf.validref, "contains substring matches, "
		    "but substring matches are unsupported." );
	goto validation_failed;
    }
    if (( ovec[ 1 ] - ovec[ 0 ] ) != strlen( dest->ptr )) {
	log_error_write( srv, __FILE__, __LINE__, "sb",
		    "mod_cosign: invalid destination (partial match):", dest );
	goto validation_failed;
    }
		
    /* validate service cookie. */
    if ( !validchars( cookie->ptr )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		"mod_cosign: cookie contains invalid characters" );
	goto validation_failed;
    }

    ipaddr = inet_ntoa( con->dst_addr.ipv4.sin_addr );

    cv = cosign_cookie_valid( p->pd_cfg, cookie->ptr, &rekey,
				&si, ipaddr, srv );
    switch ( cv ) {
    default:
    case COSIGN_ERROR:
	/* it's all forbidden! */
	con->http_status = 503;			/* "service unavailable" */
	con->mode = DIRECT;
	con->file_finished = 1;

	buffer_free( dest );
	buffer_free( cookie );
	if ( rekey != NULL ) {
	    free( rekey );
	}

	return( HANDLER_FINISHED );

    case COSIGN_RETRY:
	/*
	 * all previous versions of the filter redirect in this case. prior to
	 * cosign3, the filter would generate a new cookie and redirect to the
	 * cgi for (potentially) a new login. in the cosign3 apache filters,
	 * we're currently redirecting to dest (which has already been
	 * validated against the validref regex) and letting the filter (i.e.,
	 * cosign_auth) deal with it. this almost certainly means another
	 * redirect to the cgi, which checks the cosign cookie (valid),
	 * generates a new service cookie and registers it with the cosign
	 * cookie, then redirects to the service's handler URL with the new
	 * service cookie and destination URL in the query string. if
	 * cosign_cookie_valid returns COSIGN_RETRY again, we follow exactly
	 * the same steps until the browser reports a redirect loop. not good,
	 * but not quite sure what to do in the meantime. improved logging of
	 * 5xx statuses on the daemon will help troubleshoot the problem.
	 */
	response_header_insert( srv, con, CONST_STR_LEN( "Location" ),
					CONST_BUF_LEN( dest ));

	buffer_free( dest );
	buffer_free( cookie );
	if ( rekey != NULL ) {
	    free( rekey );
	}

	con->http_status = 301;			/* "moved permanently" */
	con->mode = DIRECT;
	con->file_finished = 1;
	
	return( HANDLER_FINISHED );
	
    case COSIGN_OK:
	break;
    }

    if ( rekey != NULL ) {
	buffer_free( cookie );
	cookie = buffer_init_string( rekey );
	free( rekey );
    }
    buffer_append_string_len( cookie, CONST_STR_LEN( "/" ));
    gettimeofday( &now, NULL );
    memset( timebuf, 0, sizeof( timebuf ));
    snprintf( timebuf, sizeof( timebuf ) - 1, "%lu", now.tv_sec );
    /* CONST_STR_LEN uses sizeof, so we can't use it here. */
    buffer_append_string_len( cookie, timebuf, strlen( timebuf ));
    buffer_append_string_len( cookie, CONST_STR_LEN( "; path=/" ));
    if ( strncmp( dest->ptr, "https://", strlen( "https://" )) == 0 ) {
	/* secure connection, secure cookie. */
	buffer_append_string_len( cookie, CONST_STR_LEN( "; secure" ));
    }

    response_header_insert( srv, con, CONST_STR_LEN( "Set-Cookie" ),
					CONST_BUF_LEN( cookie ));
    response_header_insert( srv, con, CONST_STR_LEN( "Location" ),
					CONST_BUF_LEN( dest ));
    buffer_free( cookie );
    buffer_free( dest );

    con->http_status = 301;		/* "moved permanently" */
    con->mode = DIRECT;
    con->file_finished = 1;

    return( HANDLER_FINISHED );

validation_failed:
    if ( cookie != NULL ) {
	buffer_free( cookie );
    }
    if ( dest != NULL ) {
	buffer_free( dest );
    }

    response_header_insert( srv, con, CONST_STR_LEN( "Location" ),
					CONST_BUF_LEN( p->conf.referr ));

    con->http_status = 301;		/* "moved permanently" */
    con->mode = DIRECT;
    con->file_finished = 1;

    return( HANDLER_FINISHED );
}

    static int
cosign_auth( server *srv, connection *con, plugin_data *p_d )
{
    plugin_data		*p = p_d;
    data_string		*ds = NULL;
    data_string		*cookie = NULL;
    buffer		*my_cookie = NULL;
    struct timeval	now;
    struct sinfo	si;
    time_t		cookietime = 0;
    char		*ipaddr;
    char		*data, *a, *b;
    int			cv;
#ifdef GSS
    OM_uint32		minor_status;
#endif /* GSS */

    /* we already merged the config in the handler call. */
    if ( !p->conf.protect ) {
	return( HANDLER_GO_ON );
    }

    /* verify config has been set up correctly by admin. */
    if ( buffer_is_empty( p->conf.host ) ||
		buffer_is_empty( p->conf.redirect ) ||
		buffer_is_empty( p->conf.service ) ||
		buffer_is_empty( p->conf.posterror )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		"mod_cosign: Cosign is not configured correctly." );
	if ( buffer_is_empty( p->conf.host )) {
	    log_error_write( srv, __FILE__, __LINE__, "s",
			"mod_cosign: cosign.hostname is not set." );
	}
	if ( buffer_is_empty( p->conf.redirect )) {
	    log_error_write( srv, __FILE__, __LINE__, "s",
			"mod_cosign: cosign.redirect is not set." );
	}
	if ( buffer_is_empty( p->conf.service )) {
	    log_error_write( srv, __FILE__, __LINE__, "s",
			"mod_cosign: cosign.service is not set." );
	}
	if ( buffer_is_empty( p->conf.posterror )) {
	    log_error_write( srv, __FILE__, __LINE__, "s",
			"mod_cosign: cosign.post-error is not set." );
	}

	con->http_status = 503;		/* "service unavailable" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( HANDLER_FINISHED );
    }

    if (( cookie = (data_string *)array_get_element( con->request.headers,
							"Cookie" )) == NULL ) {
	goto redirect;
    }

    data = cookie->value->ptr;
    while ( data && *data ) {
	while ( *data == ' ' ) { data++; };
	if (( a = strchr( data, ';' )) == NULL && *data == '\0' ) {
	    break;
	}
	if (( b = strchr( data, '=' )) == NULL ) {
	    continue;
	}
	if ( strncasecmp( data, p->conf.service->ptr, ( b - data )) == 0 ) {
	    if ( a ) { *a = '\0'; }
	    my_cookie = buffer_init_string( data );
	    if ( a ) { *a = ';'; }
	    break;
	}

	if (( data = a ) != NULL ) {
	    data++;
	}
    }
    if ( my_cookie == NULL || my_cookie->used < 120 ) {
	goto redirect;
    }

    /* if it's a stale cookie, give out a new one. */
    gettimeofday( &now, NULL );
    if (( a = strrchr( my_cookie->ptr, '/' )) != NULL ) {
	b = a;
	b++;
	cookietime = atoi( b );
    }
    if ( cookietime > 0 && ( now.tv_sec - cookietime ) > p->conf.expiretime ) {
	goto redirect;
    }

    if ( a ) { *a = '\0'; }
    if ( !validchars( my_cookie->ptr )) {
	goto redirect;
    }

    ipaddr = inet_ntoa( con->dst_addr.ipv4.sin_addr );

    cv = cosign_cookie_valid( p->pd_cfg, my_cookie->ptr, NULL,
				&si, ipaddr, srv );
    if ( a ) { *a = '/'; }

    if ( cv == COSIGN_ERROR ) {
	con->http_status = 503;			/* "service unavailable" */
	con->mode = DIRECT;
	con->file_finished = 1;

	return( HANDLER_FINISHED );
    }

    if ( cv == COSIGN_OK ) {
	buffer_copy_string_len( con->authed_user, si.si_user,
		strlen( si.si_user ));

	/*
	 * set environment. array_insert_unique does not copy data, so
	 * call data_string_init for each environment variable.
	 */
	if (( ds = (data_string *)array_get_unused_element( con->environment,
					TYPE_STRING )) == NULL ) {
	    ds = data_string_init();
	}
	buffer_copy_string_len( ds->key, CONST_STR_LEN( "COSIGN_SERVICE" ));
	buffer_copy_string_len( ds->value, CONST_BUF_LEN( p->conf.service ));
	array_insert_unique( con->environment, (data_unset *)ds );

	if (( ds = (data_string *)array_get_unused_element( con->environment,
					TYPE_STRING )) == NULL ) {
	    ds = data_string_init();
	}
	buffer_copy_string_len( ds->key, CONST_STR_LEN( "REMOTE_REALM" ));
	buffer_copy_string_len( ds->value, si.si_realm, strlen( si.si_realm ));
	array_insert_unique( con->environment, (data_unset *)ds );

	if (( ds = (data_string *)array_get_unused_element( con->environment,
					TYPE_STRING )) == NULL ) {
	    ds = data_string_init();
	}
	buffer_copy_string_len( ds->key, CONST_STR_LEN( "COSIGN_FACTOR" ));
	buffer_copy_string_len( ds->value, si.si_factor, strlen(si.si_factor));
	array_insert_unique( con->environment, (data_unset *)ds );

#ifdef KRB
	if ( p->conf.krbtkt == 1 ) {
	    if (( ds = (data_string *)array_get_unused_element(
					    con->environment,
					    TYPE_STRING )) == NULL ) {
		ds = data_string_init();
	    }
	    buffer_copy_string_len( ds->key, CONST_STR_LEN( "KRB5CCNAME" ));
	    buffer_copy_string_len( ds->value, si.si_krb5tkt,
			strlen( si.si_krb5tkt ));
	    array_insert_unique( con->environment, (data_unset *)ds );

#ifdef GSS
	    if ( p->conf.gss == 1 ) {
		if ( gss_krb5_ccache_name( &minor_status,
			    si.si_krb5tkt, NULL ) != GSS_S_COMPLETE ) {
		    log_error_write( srv, __FILE__, __LINE__, "s",
			    "mod_cosign: gss_krb5_ccache_name failed." );
		}
	    }
#endif /* GSS */
	}
#endif /* KRB */

	return( HANDLER_GO_ON );
    }

    /* COSIGN_RETRY (5xx status from cosignd) falls through to redirect. */

redirect:
    /* let them thru regardless if this is "public" */
    if ( p->conf.public == 1 ) {
	return( HANDLER_GO_ON );
    }

    if ( cosign_redirect( srv, con, p ) != 0 ) {
	con->http_status = 503;		/* "service unavailable" */
    } else {
	con->http_status = 302;		/* "moved temporarily" */
    }
    con->mode = DIRECT;
    con->file_finished = 1;

    return( HANDLER_FINISHED );
}

URIHANDLER_FUNC( mod_cosign_uri_handler )
{
    plugin_data		*p = p_d;
    handler_t		rc;

    UNUSED(srv);

    if ( con->mode != DIRECT ) {
	return( HANDLER_GO_ON );
    }

    mod_cosign_patch_connection( srv, con, p );

    if ( p->conf.handleruri == NULL || buffer_is_empty( p->conf.handleruri )) {
	log_error_write( srv, __FILE__, __LINE__, "s",
		"mod_cosign: cosign.validation-handler-uri not set" );
	return( HANDLER_ERROR );
    }
    if ( buffer_is_equal( con->uri.path, p->conf.handleruri )) {
	if (( rc = cosign_handler( srv, con, p )) != HANDLER_GO_ON ) {
	    return( rc );
	}
    }

    return( cosign_auth( srv, con, p ));
}

/* this function is called at dlopen() time and inits the callbacks */

    int
mod_cosign_plugin_init( plugin *p ) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name = buffer_init_string( "cosign" );

    p->init = mod_cosign_init;
    p->handle_uri_clean = mod_cosign_uri_handler;
    p->set_defaults = mod_cosign_set_defaults;
    p->cleanup = mod_cosign_free;

    p->data = NULL;

    return( 0 );
}

/*
 * shim to convert between lighttpd's nasty logging API and something
 * resembling sanity.
 */
    void
cosign_log( int level, server *srv, char *fmt, ... )
{
    va_list		vl;
    char		*msg = NULL;
    
    va_start( vl, fmt );
    if ( vasprintf( &msg, fmt, vl ) < 0 ) {
	abort();
    }
    va_end( vl );
    log_error_write((server *)srv, __FILE__, __LINE__, "s", msg );
    free( msg );
}

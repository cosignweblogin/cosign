/*
 *  mod_cosign.c -- Apache sample cosign module
 */ 

#include "config.h"

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_connection.h>
#include <http_request.h>
#include <apr_strings.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#ifdef KRB
#ifdef GSS
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif /* GSS */
#endif /* KRB */

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "argcargv.h"
#include "sparse.h"
#include "mkcookie.h"
#include "cosign.h"
#include "cosignpaths.h"
#include "log.h"

static int	cosign_redirect( request_rec *, cosign_host_config * );

/* Our exported link to Apache. */
module AP_MODULE_DECLARE_DATA cosign_module;

    static void *
cosign_create_config( apr_pool_t *p )
{
    cosign_host_config *cfg;

    cfg = (cosign_host_config *)apr_pcalloc( p, sizeof( cosign_host_config ));
    cfg->service = NULL;
    cfg->siteentry = NULL;
    cfg->reqfv = NULL;
    cfg->reqfc = -1;
    cfg->suffix = NULL;
    cfg->fake = -1;
    cfg->public = -1;
    cfg->redirect = NULL;
    cfg->posterror = NULL;
    cfg->validref = NULL;
    cfg->validpreg = NULL;
    cfg->validredir = -1;
    cfg->referr = NULL;
    cfg->port = 0;
    cfg->protect = -1;
    cfg->configured = 0;
    cfg->checkip = IPCHECK_NEVER;
    cfg->cl = NULL;
    cfg->ctx = NULL;
    cfg->key = NULL;
    cfg->cert = NULL;
    cfg->cadir = NULL;
    cfg->filterdb = _FILTER_DB;
    cfg->hashlen = 0;
    cfg->proxydb = _PROXY_DB;
    cfg->tkt_prefix = _COSIGN_TICKET_CACHE;
    cfg->http = -1;
    cfg->noappendport = -1;
    cfg->proxy = -1;
    cfg->expiretime = 86400; /* 24 hours */
    cfg->httponly_cookies = 0;
#ifdef KRB
    cfg->krbtkt = -1;
#ifdef GSS
    cfg->gss = -1;
#endif /* GSS */
#endif /* KRB */
    return( cfg );
}


    static void *
cosign_create_dir_config( apr_pool_t *p, char *path )
{
    return( cosign_create_config( p ));
}

    static void *
cosign_create_server_config( apr_pool_t *p, server_rec *s )
{
    cosign_host_config		*cfg;

    cfg = cosign_create_config( p );

    /* assign a reasonable default CosignService */
    cfg->service = apr_psprintf( p, "cosign-%s", s->server_hostname );

    return( cfg );
}

    static int
cosign_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    extern char	*cosign_version;

    cosign_log( APLOG_NOTICE, s, "mod_cosign: version %s initialized.",
		cosign_version );
    return( OK );
}

    int
cosign_redirect( request_rec *r, cosign_host_config *cfg )
{
    char		*dest;
    char                *ref, *reqfact;
    int                 i;
    unsigned int	port;
    struct timeval      now;

    /* if they've posted, let them know they are out of luck */
    if ( r->method_number == M_POST ) {
	dest = apr_psprintf( r->pool, "%s", cfg->posterror );
	apr_table_set( r->headers_out, "Location", dest );
	return( 0 );
    }

    /*
     * clear out Cache-Control and Expires headers, and preemptively set
     * Cache-Control header to keep aggressive caching configurations from
     * breaking cosign auth. if the browser caches the 302 redirect, the
     * redirect from the validation handler to the protected site will
     * result in the browser revisiting the weblogin server instead.
     */
    apr_table_unset( r->headers_out, "Cache-Control" );
    apr_table_unset( r->headers_out, "Expires" );

    apr_table_set( r->headers_out, "Cache-Control", "no-cache" );

    if ( cfg->siteentry != NULL && strcasecmp( cfg->siteentry, "none" ) != 0 ) {
	ref = cfg->siteentry;
    } else {
	/* live dangerously, we're redirecting to http */
	if ( cfg->http == 1 ) {
	    if ((( port = ap_get_server_port( r )) == 80 ) ||
		    ( cfg->noappendport == 1 )) {
		ref = apr_psprintf( r->pool, "http://%s%s",
			ap_get_server_name( r ), r->unparsed_uri );
	    } else {
		ref = apr_psprintf( r->pool, "http://%s:%d%s",
			ap_get_server_name( r ), port, r->unparsed_uri );
	    }
	/* live securely, redirecting to https */
	} else {
	    if ((( port = ap_get_server_port( r )) == 443 ) ||
		    ( cfg->noappendport == 1 )) {
		ref = apr_psprintf( r->pool, "https://%s%s",
			ap_get_server_name( r ), r->unparsed_uri );
	    } else {
		ref = apr_psprintf( r->pool, "https://%s:%d%s",
			ap_get_server_name( r ), port, r->unparsed_uri );
	    }
	}
    }

    if ( cfg->reqfc > 0 ) {
        reqfact = apr_pstrcat( r->pool, "factors=", cfg->reqfv[ 0 ], NULL );
        for ( i = 1; i < cfg->reqfc; i++ ) {
            reqfact = apr_pstrcat( r->pool, reqfact, ",",
                    cfg->reqfv[ i ], NULL );
        }
        dest = apr_psprintf( r->pool,
                "%s?%s&%s&%s", cfg->redirect, reqfact, cfg->service, ref );
    } else {
        dest = apr_psprintf( r->pool,
                "%s?%s&%s", cfg->redirect, cfg->service, ref );
    }
    apr_table_set( r->headers_out, "Location", dest );
    return( 0 );
}

    static int
cosign_handler( request_rec *r )
{
    cosign_host_config	*cfg;
    ap_regmatch_t	matches[ 1 ];
    apr_uri_t		uri;
    apr_port_t		port;
    apr_status_t	status;
    char		error[ 1024 ];
    const char		*qstr = NULL;
    const char		*pair, *key;
    const char		*dest = NULL;
    const char		*hostname, *scheme;
    char		*cookie, *full_cookie;
    char		*rekey = NULL;
    int			rc, cv;
    struct sinfo	si;
    struct timeval	now;

    if ( !r->handler || strcmp( r->handler, "cosign" ) != 0 ) {
	return( DECLINED );
    }
    if ( r->method_number != M_GET ) {
	return( HTTP_METHOD_NOT_ALLOWED );
    }

    cfg = (cosign_host_config *)ap_get_module_config( r->server->module_config,
						      &cosign_module );
    if ( !cfg->configured ) {
	cosign_log( APLOG_ERR, r->server, "mod_cosign not configured" );
	return( HTTP_SERVICE_UNAVAILABLE );
    }
    if ( cfg->validref == NULL ) {
	cosign_log( APLOG_ERR, r->server,
			"mod_cosign: CosignValidReference not set." );
	return( HTTP_SERVICE_UNAVAILABLE );
    }
    if ( cfg->referr == NULL ) {
	cosign_log( APLOG_ERR, r->server,
			"mod_cosign: CosignValidationErrorRedirect not set." );
	return( HTTP_SERVICE_UNAVAILABLE );
    }

    if (( qstr = r->args ) == NULL ) {
	cosign_log( APLOG_NOTICE, r->server,
			"mod_cosign: no query string passed to handler." ); 
	return( HTTP_FORBIDDEN );
    }

    /* get cookie from query string */
    pair = ap_getword( r->pool, &qstr, '&' );
    if ( strncasecmp( pair, "cosign-", strlen( "cosign-" )) != 0 ) {
	( void )strtok((char *)pair, "=" );
	cosign_log( APLOG_NOTICE, r->server,
			"mod_cosign: invalid service \"%s\"", pair );
	goto validation_failed;
    }
    /* retain a copy of the complete string to use when we set the cookie */
    cookie = apr_pstrdup( r->pool, pair );

    /*
     * ap_getword modifies qstr, extracting the service cookie. the remainder
     * of the query string is assumed to be the destination URL.
     */
    if (( dest = qstr ) == NULL ) {
	cosign_log( APLOG_NOTICE, r->server,
			"mod_cosign: no destination URL in query string" );

	goto validation_failed;
    }
    if (( rc = ap_regexec( cfg->validpreg, dest, 1, matches, 0 )) != 0 ) {
	if ( rc != AP_REG_NOMATCH ) {
	    ap_regerror( rc, cfg->validpreg, error, sizeof( error ));
	    cosign_log( APLOG_ERR, r->server,
			"mod_cosign: ap_regexec %s: %s", dest, error );
	    return( HTTP_INTERNAL_SERVER_ERROR );
	}
	
	cosign_log( APLOG_NOTICE, r->server,
			"mod_cosign: invalid destination: %s", dest );
	goto validation_failed;
    }
    if ( matches[ 0 ].rm_so != 0 || matches[ 0 ].rm_eo != strlen( dest )) {
	cosign_log( APLOG_NOTICE, r->server, "mod_cosign: "
		    "invalid destination: %s (partial match)", dest );
	goto validation_failed;
    }

    /* validate service cookie */
    if ( !validchars( cookie )) {
	cosign_log( APLOG_NOTICE, r->server,
			"mod_cosign: cookie contains invalid characters" );
	goto validation_failed;
    }

    /*
     * if the current URL hostname doesn't match the hostname of the
     * service URL, we'll end up setting the cookie for the wrong domain.
     * we catch that here and consider it an error unless the admin has
     * CosignAllowValidationRedirect set to On, in which case we extract
     * the hostname from the service URL and use it to build a validation
     * URL for the correct host.
     */
    if (( status = apr_uri_parse( r->pool, dest, &uri )) != APR_SUCCESS ) {
	apr_strerror( status, error, sizeof( error ));
	cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: apr_uri_parse %s: %s", dest, error );
	return( HTTP_INTERNAL_SERVER_ERROR );
    }
    if ( uri.scheme == NULL || uri.hostname == NULL ) {
	cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: bad destination URL: %s", dest );
	return( HTTP_BAD_REQUEST );
    }
    if ( uri.port == 0 ) {
	uri.port = apr_uri_port_of_scheme( uri.scheme );
    }
    hostname = ap_get_server_name( r );
    port = ap_get_server_port( r );
    if ( strcasecmp( hostname, uri.hostname ) != 0 ||
		( port != uri.port && cfg->noappendport != 1 )) {
	if ( cfg->validredir == 1 ) {
	    /* always redirect to https unless CosignHttpOnly is enabled. */
	    if ( cfg->http == 1 ) {
		scheme = "http";
	    } else {
		scheme = "https";
	    }
	    if ( port != uri.port ) {
		dest = apr_psprintf( r->pool, "%s://%s:%d%s",
			    scheme, uri.hostname, uri.port, r->unparsed_uri );
	    } else {
		dest = apr_psprintf( r->pool, "%s://%s%s",
			    scheme, uri.hostname, r->unparsed_uri );
	    }
	    apr_table_set( r->headers_out, "Location", dest );

	    return( HTTP_MOVED_PERMANENTLY );
	} else {
	    cosign_log( APLOG_ERR, r->server,
			"mod_cosign: current hostname \"%s\" does not match "
			"service URL hostname \"%s\", cannot set cookie for "
			"correct domain.", hostname, uri.hostname );

	    return( HTTP_SERVICE_UNAVAILABLE );
	}
    }

    cv = cosign_cookie_valid( cfg, cookie, &rekey, &si,
		r->connection->remote_ip, r->server );
    if ( rekey != NULL ) {
	/* we got a rekeyed cookie. let the request pool free it later. */
	apr_pool_cleanup_register( r->pool, (void *)rekey, (void *)free,
					apr_pool_cleanup_null );

	cookie = rekey;
    }
    switch ( cv ) {
    default:
    case COSIGN_ERROR:
	return( HTTP_SERVICE_UNAVAILABLE );	/* it's all forbidden! */

    case COSIGN_RETRY:
	/*
	 * Don't set cookie, but redirect to service URL
	 * and let filter deal with it. May result in a
	 * redirect back to central login page. 
	 */
	apr_table_set( r->headers_out, "Location", dest );
	return( HTTP_MOVED_PERMANENTLY );

    case COSIGN_OK:
	break;
    }

    gettimeofday( &now, NULL );
    if ( strncmp( dest, "http://", strlen( "http://" )) == 0 ) {
	/* if we're redirecting to http, can set insecure cookie */
	full_cookie = apr_psprintf( r->pool, "%s/%lu; path=/",
				    cookie, now.tv_sec );
    } else {
	full_cookie = apr_psprintf( r->pool, "%s/%lu; path=/; secure",
				    cookie, now.tv_sec );
    }
    if ( cfg->httponly_cookies == 1 ) {
	full_cookie = apr_pstrcat( r->pool, full_cookie, "; httponly", NULL );
    }

    /* we get here, everything's OK. set the cookie and redirect to dest. */
    apr_table_set( r->err_headers_out, "Set-Cookie", full_cookie );
    apr_table_set( r->headers_out, "Location", dest );

    return( HTTP_MOVED_PERMANENTLY );

validation_failed:
    apr_table_set( r->headers_out, "Location", cfg->referr );

    return( HTTP_MOVED_PERMANENTLY );
}

    static int
cosign_authn( request_rec *r )
{
    const char *authn;
    cosign_host_config  *cfg;

    cfg = (cosign_host_config *)ap_get_module_config(
            r->per_dir_config, &cosign_module);
    if ( !cfg->configured ) {
        cfg = (cosign_host_config *)ap_get_module_config(
                r->server->module_config, &cosign_module);
    }

    if (( authn = ap_auth_type( r )) == NULL ) {
        return( DECLINED );
    }

    if ( strcasecmp( authn, "Cosign" ) != 0 ) {
        return( DECLINED );
    }

    if ( apr_table_get( r->notes, "cosign-redirect" ) != NULL ) {
        if ( cosign_redirect( r, cfg ) != 0 ) {
            return( HTTP_SERVICE_UNAVAILABLE );
        }
        return( HTTP_MOVED_TEMPORARILY );
    }

    if ( r->user == NULL ) {
        return( DECLINED );
    }

    /* we OK here to claim this as our AuthZ call.
     * otherwise, we'll get a 503 as basic auth will
     * try and nab it, but things won't be set up
     * for basicauth's needs. So that would be bad.
     */
    return( OK );
}


    static int
cosign_auth( request_rec *r )
{
    const char		*cookiename = NULL;
    const char		*data = NULL, *pair = NULL;
    char		*misc = NULL;
    char		*my_cookie;
    int			cv;
    int			cookietime = 0;
    struct sinfo	si;
    cosign_host_config	*cfg;
    struct timeval	now;
#ifdef GSS
    OM_uint32		minor_status;
#endif /* GSS */

    /*
     * Select the correct cfg
     */
    cfg = (cosign_host_config *)ap_get_module_config(
	    r->per_dir_config, &cosign_module);
    if ( !cfg->configured ) {
	cfg = (cosign_host_config *)ap_get_module_config(
		r->server->module_config, &cosign_module);
    }

    if ( !cfg->configured || cfg->protect == 0 ) {
	return( DECLINED );
    }

    /*
     * Verify cfg has been setup correctly by admin
     */

    if (( cfg->host == NULL ) || ( cfg->redirect == NULL ) ||
		( cfg->service == NULL || cfg->posterror == NULL )) {
	cosign_log( APLOG_ERR, r->server,
		"mod_cosign: Cosign is not configured correctly:" );
	if ( cfg->host == NULL ) {
	    cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: CosignHostname not set." );
	}
	if ( cfg->redirect == NULL ) {
	    cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: CosignRedirect not set." );
	}
	if ( cfg->service == NULL ) {
	    cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: CosignService not set." );
	}
	if ( cfg->posterror == NULL ) {
	    cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: CosignPostErrorRedirect not set." );
	}
	return( HTTP_SERVICE_UNAVAILABLE );
    }

    /* Look for cfg->service cookie. if there isn't one, redirect. */
    if (( data = apr_table_get( r->headers_in, "Cookie" )) == NULL ) {
	goto redirect;
    }

    while ( *data && ( pair = ap_getword( r->pool, &data, ';' ))) {
	cookiename = ap_getword( r->pool, &pair, '=' );
	if ( strcasecmp( cookiename, cfg->service ) == 0 ) {
	    break;
	}
	cookiename = NULL;
	while ( *data == ' ' ) { data++; }
    }

    if (( cookiename == NULL ) || ( strlen( pair ) < 120 )) {
	goto redirect;
    }
    my_cookie = apr_psprintf( r->pool, "%s=%s", cookiename, pair );

    /* if it's a stale cookie, give out a new one */
    gettimeofday( &now, NULL );
    (void)strtok( my_cookie, "/" );
    if (( misc = strtok( NULL, "/" )) != NULL ) {
        cookietime = atoi( misc );
    }
    if (( cookietime > 0 ) && ( now.tv_sec - cookietime ) > cfg->expiretime ) {
        goto redirect;
    }

    if ( !validchars( my_cookie )) {
	goto redirect;
    }

    /*
     * Validate cookie with backside server.  If we already have a cached
     * version of the data, just verify the cookie's still valid.
     * Otherwise, retrieve the auth info from the server.
     */
    cv = cosign_cookie_valid( cfg, my_cookie, NULL, &si,
		r->connection->remote_ip, r->server );
    if ( cv == COSIGN_ERROR ) {
	return( HTTP_SERVICE_UNAVAILABLE );	/* it's all forbidden! */
    } 

    /* Everything Shines, let them thru */
    if ( cv == COSIGN_OK ) {
	r->user = apr_pstrcat( r->pool, si.si_user, NULL);
	r->ap_auth_type = "Cosign";
	apr_table_set( r->subprocess_env, "COSIGN_SERVICE", cfg->service );
	apr_table_set( r->subprocess_env, "REMOTE_REALM", si.si_realm );
	apr_table_set( r->subprocess_env, "COSIGN_FACTOR", si.si_factor );

#ifdef KRB
	if ( cfg->krbtkt == 1 ) {
	    apr_table_set( r->subprocess_env, "KRB5CCNAME", si.si_krb5tkt );
#ifdef GSS
	if ( cfg->gss == 1 ) {
	    if ( gss_krb5_ccache_name( &minor_status, si.si_krb5tkt, NULL )
		    != GSS_S_COMPLETE ) {
		cosign_log( APLOG_ERR,
			 r->server, "mod_cosign: gss_krb5_ccache_name" );
	    }
	}
#endif /* GSS */
	}
#endif /* KRB */
	return( DECLINED );
    }

    /* if we get here, this is also the fall through if cv == COSIGN_RETRY */

redirect:
    /* let them thru regardless if this is "public" */
    if ( cfg->public == 1 ) {
        return( DECLINED );
    }
#ifdef notdef
    /*
     * This is probably wrong.  We should only send a Location header just
     * before we return 300.
     */
    if ( cosign_redirect( r, cfg ) != 0 ) {
        return( HTTP_SERVICE_UNAVAILABLE );
    }
#endif /* notdef */
    if ( ap_some_auth_required( r )) {
        apr_table_setn( r->notes, "cosign-redirect", "true" );
        return( DECLINED );
    } else {
        if ( cosign_redirect( r, cfg ) != 0 ) {
            return( HTTP_SERVICE_UNAVAILABLE );
        }
        return( HTTP_MOVED_TEMPORARILY );
    }

}
    static cosign_host_config *
cosign_merge_cfg( cmd_parms *params, void *mconfig )
{
    cosign_host_config          *cfg, *scfg;

    /* apache's built-in (request time) merge is for directories only or
     * servers only, there's no way to inherit server config in a directory.
     * So we do that here. Do note that because this is a config time merge,
     * this has a side effect of requiring all server-wide directives to
     * preecede the directory or location specific ones in the config file.
     */

    scfg = (cosign_host_config *) ap_get_module_config(
                params->server->module_config, &cosign_module );
    if ( params->path == NULL ) {
        return( scfg );
    }

    cfg = (cosign_host_config *)mconfig;
    if ( cfg->siteentry == NULL ) {
        cfg->siteentry = apr_pstrdup( params->pool, scfg->siteentry );
    }
    if ( cfg->reqfv == NULL ) {
        cfg->reqfv = scfg->reqfv;
    }
    if ( cfg->reqfc == -1 ) {
        cfg->reqfc = scfg->reqfc;
    }
    if ( cfg->suffix == NULL ) {
        cfg->suffix = apr_pstrdup( params->pool, scfg->suffix );
    }
    if ( cfg->fake == -1 ) {
        cfg->fake = scfg->fake;
    }
    if ( cfg->public == -1 ) {
        cfg->public = scfg->public;
    }
    if ( cfg->protect == -1 ) {
        cfg->protect = scfg->protect;
    }

    cfg->filterdb = apr_pstrdup( params->pool, scfg->filterdb );
    cfg->hashlen =  scfg->hashlen;
    cfg->checkip =  scfg->checkip;
    cfg->proxydb = apr_pstrdup( params->pool, scfg->proxydb );
    cfg->tkt_prefix = apr_pstrdup( params->pool, scfg->tkt_prefix );

    if ( cfg->service == NULL ) {
        cfg->service = apr_pstrdup( params->pool, scfg->service );      
    }
    if ( cfg->redirect == NULL ) {
        cfg->redirect = apr_pstrdup( params->pool, scfg->redirect );
    }
    if ( cfg->host == NULL ) {
        cfg->host = apr_pstrdup( params->pool, scfg->host );
    }
    if ( cfg->posterror == NULL ) {
        cfg->posterror = apr_pstrdup( params->pool, scfg->posterror );
    }
    if ( cfg->port == 0 ) {
        cfg->port = scfg->port;
    }
    if ( cfg->cl == NULL ) {
        cfg->cl = scfg->cl;
    }
    if ( cfg->ctx == NULL ) {
        cfg->ctx = scfg->ctx;
    }
    if ( cfg->proxy == -1 ) {
        cfg->proxy = scfg->proxy;
    }
    if ( cfg->http == -1 ) {
        cfg->http = scfg->http;
    }
    if ( cfg->noappendport == -1 ) {
	cfg->noappendport = scfg->noappendport;
    }

    cfg->expiretime = scfg->expiretime;

#ifdef KRB
    if ( cfg->krbtkt == -1 ) {
        cfg->krbtkt = scfg->krbtkt;
    }
#ifdef GSS
    if ( cfg->gss == -1 ) {
        cfg->gss = scfg->gss;
    }
#endif /* GSS */
#endif /* KRB */

    return( cfg );
}

    static const char *
set_cosign_protect( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->protect = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_post_error( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->posterror = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_valid_reference( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->validref = apr_pstrdup( params->pool, arg );
    if (( cfg->validpreg = ap_pregcomp( params->pool, cfg->validref,
		AP_REG_EXTENDED )) == NULL ) {
	cosign_log( APLOG_ERR, params->server,
		"mod_cosign: set_cosign_valid_reference: ap_pregcomp %s failed",
		cfg->validref );
	return( "ap_pregcomp failed" );
    }

    cfg->configured = 1;

    return( NULL );
}

    static const char *
set_cosign_allow_validation_redirect( cmd_parms *params,
					void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->validredir = flag;

    return( NULL );
}

    static const char *
set_cosign_validation_error_redirect( cmd_parms *params,
					void *mconfig, const char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->referr = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;

    return( NULL );
}

    static const char *
set_cosign_service( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    if ( strncmp( arg, "cosign-", strlen( "cosign-" )) == 0 ) {
	cfg->service = apr_pstrdup( params->pool, arg );
    } else {
	cfg->service = apr_psprintf( params->pool, "cosign-%s", arg );
    }

    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_siteentry( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->siteentry = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_checkip( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    if ( strcasecmp( arg, "never" ) == 0 ) {
        cfg->checkip = IPCHECK_NEVER;
    } else if ( strcasecmp( arg, "initial" ) == 0 ) {
        cfg->checkip = IPCHECK_INITIAL;
    } else if ( strcasecmp( arg, "always" ) == 0 ) {
        cfg->checkip = IPCHECK_ALWAYS;
    } else {
        return( "CosignCheckIP must be never, initial, or always.");
    }
    return( NULL );
}


    static const char *
set_cosign_factor( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;
    ACAV                        *acav;
    int                         ac, i;
    char                        **av;
    char                        *arg0;

    cfg = cosign_merge_cfg( params, mconfig );

    if (( acav = acav_alloc()) == NULL ) {
        cosign_log( APLOG_ERR, params->server, "mod_cosign: set_cosign_factor:"
                " acav_alloc failed" );
        exit( 1 );
    }

    arg0 = apr_pstrdup( params->pool, arg );
    if (( ac = acav_parse( acav, arg0, &av )) < 0 ) {
        cosign_log( APLOG_ERR, params->server, "mod_cosign: set_cosign_factor:"
                " acav_parse failed" );
        exit( 1 );
    }

    /* should null terminate av */
    cfg->reqfv = apr_palloc( params->pool, ac * sizeof( char * ));
    for ( i = 0; i < ac; i++ ) {
        cfg->reqfv[ i ] = apr_pstrdup( params->pool, av[ i ] );
    }
    cfg->reqfc = ac;

    acav_free( acav );

    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_factorsuffix( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->suffix = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_ignoresuffix( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->fake = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_public( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->public = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_port( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config  *cfg;
    int			 portarg;
    struct connlist	 *cur;

    cfg = cosign_merge_cfg( params, mconfig );

    portarg = strtol( arg, (char **)NULL, 10 );
    cfg->port = htons( portarg );

    for ( cur = *(cfg->cl); cur != NULL; cur = cur->conn_next ) {
        if ( cfg->port == 0 ) {
            cur->conn_sin.sin_port = htons( 6663 );
        } else {
            cur->conn_sin.sin_port = cfg->port;
        }
    }
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_redirect( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->redirect = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_filterdb( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (cosign_host_config *) ap_get_module_config(
                params->server->module_config, &cosign_module );
    } else {
        return( "CosignFilterDB not valid per dir!" );
    }

    cfg->filterdb = apr_pstrdup( params->pool, arg );
    return( NULL );
}

    static const char *
set_cosign_hashlen( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (cosign_host_config *) ap_get_module_config(
                params->server->module_config, &cosign_module );
    } else {
        return( "CosignFilterHashLength not valid per dir!" );
    }

    cfg->hashlen = strtol( arg, (char **)NULL, 10 );
    if (( cfg->hashlen < 0 ) || ( cfg->hashlen > 2 )) {
        return( "CosignFilterHashLength must be 0, 1, or 2.");
    }
    return( NULL );
}

    static const char *
set_cosign_proxydb( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (cosign_host_config *) ap_get_module_config(
                params->server->module_config, &cosign_module );
    } else {
        return( "CosignProxyDB not valid per dir!" );
    }

    cfg->proxydb = apr_pstrdup( params->pool, arg );
    return( NULL );
}

    static const char *
set_cosign_tkt_prefix( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (cosign_host_config *) ap_get_module_config(
                params->server->module_config, &cosign_module );
    } else {
        return( "CosignTicketPrefix not valid per dir!" );
    }

    cfg->tkt_prefix = apr_pstrdup( params->pool, arg );
    return( NULL );
}

#ifdef KRB
#ifdef GSS
    static const char *
set_cosign_gss( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->gss = flag; 
    cfg->configured = 1; 
    return( NULL );
}
#endif /* GSS */

    static const char *
set_cosign_tickets( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->krbtkt = flag; 
    cfg->configured = 1; 
    return( NULL );
}
#endif /* KRB */

    static const char *
set_cosign_proxy_cookies( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->proxy = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_certs( cmd_parms *params, void *mconfig,
	const char *one, const char *two, const char *three)
{
    cosign_host_config		*cfg;
    struct stat			st;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->key = apr_pstrdup( params->pool, one );
    cfg->cert = apr_pstrdup( params->pool, two );
    cfg->cadir = apr_pstrdup( params->pool, three );

    if (( cfg->key == NULL ) || ( cfg->cert == NULL ) ||
	    ( cfg->cadir == NULL)) {
	return( "You know you want the crypto!" );
    }

    if ( stat( cfg->cadir, &st ) != 0 ) {
	return( "An error occurred checking the CAdir." );
    }

    if ( access( cfg->key, R_OK ) != 0 ) {
	return( "An error occured reading the Keyfile." );
    }

    if ( access( cfg->cert, R_OK ) != 0 ) {
	return( "An error occured reading the Certfile." );
    }

    if ( S_ISDIR( st.st_mode )) {
	if ( access( cfg->cadir, R_OK | X_OK ) != 0 ) {
	    return( "An error occured reading the CADir." );
	}
    } else if ( access( cfg->cadir, R_OK ) != 0 ) {
	return( "An error occurred reading the CAfile." );
    }

    SSL_load_error_strings();
    SSL_library_init();
    if (( cfg->ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	cosign_log( APLOG_ERR, params->server,
		"SSL_CTX_new: %s\n", ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_use_PrivateKey_file( cfg->ctx,
	    cfg->key, SSL_FILETYPE_PEM ) != 1 ) {
	cosign_log( APLOG_ERR, params->server,
		"SSL_CTX_use_PrivateKey_file: %s: %s\n",
		cfg->key, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( cfg->ctx, cfg->cert ) != 1 ) {
	cosign_log( APLOG_ERR, params->server,
		"SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cfg->cert, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_check_private_key( cfg->ctx ) != 1 ) {
	cosign_log( APLOG_ERR, params->server,
		"SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( S_ISDIR( st.st_mode )) {
	if ( SSL_CTX_load_verify_locations( cfg->ctx, NULL, cfg->cadir ) != 1) {
	    cosign_log( APLOG_ERR, params->server,
		    "SSL_CTX_load_verify_locations: CAdir %s: %s\n",
		    cfg->cadir, ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
    } else if ( SSL_CTX_load_verify_locations( cfg->ctx,
		cfg->cadir, NULL ) != 1 ) {
	cosign_log( APLOG_ERR, params->server,
		"SSL_CTX_load_verify_locations: CAfile %s: %s\n",
		cfg->cadir, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    SSL_CTX_set_verify( cfg->ctx,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL );

    return( NULL );
}

    static const char *
set_cosign_host( cmd_parms *params, void *mconfig, const char *arg )
{
    struct hostent		*he;
    int				i;
    struct connlist		*new, **cur;
    char			*err;
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->host = apr_pstrdup( params->pool, arg );
    if (( he = gethostbyname( cfg->host )) == NULL ) {
	err = apr_psprintf( params->pool, "%s: host unknown", cfg->host );
	return( err );
    }

    /* This is hairy. During operation, we re-oder the connection list
     * so that the most responsive server is at the head of the list.
     * This requires updates to the pointer to the list head from the cfg
     * structure. However, the cfg structure gets copied around when
     * Apache does configuration merges, so there isn't a single cfg
     * structure in any one process. Instead, we point to a pointer
     * to the list head. */
    cfg->cl = (struct connlist **)
	    apr_palloc(params->pool, sizeof(struct connlist*));

    /* preserve address order as returned from DNS */
    /* actually, here we will randomize for "load balancing" */
    cur = cfg->cl;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	new = ( struct connlist * )
		apr_palloc( params->pool, sizeof( struct connlist ));
	memset( &new->conn_sin, 0, sizeof( struct sockaddr_in ));
	new->conn_sin.sin_family = AF_INET;
	if ( cfg->port == 0 ) {
            new->conn_sin.sin_port = htons( 6663 );
        } else {
            new->conn_sin.sin_port = cfg->port;
        }
	memcpy( &new->conn_sin.sin_addr.s_addr,
		he->h_addr_list[ i ], ( unsigned int)he->h_length );
	new->conn_sn = NULL;
	*cur = new;
	cur = &new->conn_next;
    }
    *cur = NULL;
    return( NULL );
}

    static const char *
set_cosign_http( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->http = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_noappendport( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->noappendport = flag;
    cfg->configured = 1;
    return( NULL );
}


    static const char *
set_cosign_expiretime( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config          *cfg;

    if ( params->path == NULL ) {
        cfg = (cosign_host_config *) ap_get_module_config(
                params->server->module_config, &cosign_module );
    } else {
        /* maybe we need to rethink this */
        return( "Service cookie expiration policy applies server-wide.");
    }

    cfg->expiretime = strtol( arg, (char **)NULL, 10 );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_httponly_cookies( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );
    cfg->httponly_cookies = flag;

    return( NULL );
}

static command_rec cosign_cmds[ ] =
{
        AP_INIT_TAKE1( "CosignPostErrorRedirect", set_cosign_post_error,
        NULL, RSRC_CONF | ACCESS_CONF,
        "the URL to deliver bad news about POSTed data" ),

        AP_INIT_TAKE1( "CosignService", set_cosign_service,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "the name of the cosign service" ),

        AP_INIT_FLAG( "CosignProtected", set_cosign_protect,
        NULL, RSRC_CONF | OR_AUTHCFG, 
        "turn cosign off on a location or directory basis" ),

        AP_INIT_TAKE1( "CosignRedirect", set_cosign_redirect,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "the URL to register service cookies with cosign" ),

	AP_INIT_TAKE1( "CosignValidReference", set_cosign_valid_reference,
	NULL, RSRC_CONF | ACCESS_CONF,
	"the regular expression matching valid redirect service URLs" ),

	AP_INIT_FLAG( "CosignAllowValidationRedirect",
	set_cosign_allow_validation_redirect, NULL, RSRC_CONF | ACCESS_CONF,
	"allow redirection to different validation URL if "
	"current vhost does not match service URL hostname AND "
	"service URL matches CosignValidReference pattern" ),

	AP_INIT_TAKE1( "CosignValidationErrorRedirect",
	set_cosign_validation_error_redirect, NULL, RSRC_CONF | ACCESS_CONF,
	"where the location handler sends us in case of bad parameters" ),

        AP_INIT_TAKE1( "CosignPort", set_cosign_port,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "the port to register service cookies with cosign" ),

        AP_INIT_TAKE1( "CosignHostname", set_cosign_host,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "the name of the cosign hosts(s)" ),

        AP_INIT_TAKE1( "CosignFilterDB", set_cosign_filterdb,
        NULL, RSRC_CONF, 
        "the path to the cosign filter DB" ),

        AP_INIT_TAKE1( "CosignFilterHashLength", set_cosign_hashlen,
        NULL, RSRC_CONF, 
        "0, 1, or 2 - if you want the filter db stored in subdirs" ),

        AP_INIT_TAKE1( "CosignProxyDB", set_cosign_proxydb,
        NULL, RSRC_CONF, 
        "the path to the cosign proxy DB" ),

        AP_INIT_TAKE1( "CosignTicketPrefix", set_cosign_tkt_prefix,
        NULL, RSRC_CONF, 
        "the path to the cosign Kerberos ticket directory" ),

	AP_INIT_TAKE1( "CosignCheckIP", set_cosign_checkip,
        NULL, RSRC_CONF,
        "\"never\", \"initial\", or \"always\"" ),

        AP_INIT_TAKE1( "CosignSiteEntry", set_cosign_siteentry,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "\"none\" or URL to redirect for users who successfully authenticate" ),

        AP_INIT_RAW_ARGS( "CosignRequireFactor", set_cosign_factor,
        NULL, RSRC_CONF | OR_AUTHCFG, 
        "the authentication factors that must be satisfied" ),

        AP_INIT_TAKE1( "CosignFactorSuffix", set_cosign_factorsuffix,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "the factor suffix when testing for compliance" ),

        AP_INIT_FLAG( "CosignFactorSuffixIgnore", set_cosign_ignoresuffix,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "on or off, on allows you to accept faux factors, off denies access" ),

        AP_INIT_FLAG( "CosignAllowPublicAccess", set_cosign_public,
        NULL, RSRC_CONF | OR_AUTHCFG, 
        "make authentication optional for protected sites" ),

        AP_INIT_FLAG( "CosignHttpOnly", set_cosign_http,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "redirect to http instead of https on the local server" ),

        AP_INIT_FLAG( "CosignNoAppendRedirectPort", set_cosign_noappendport,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "for SSL load balancers - redirect with no added port to the URL" ),

        AP_INIT_TAKE3( "CosignCrypto", set_cosign_certs,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "crypto for use in talking to cosign host" ),

        AP_INIT_FLAG( "CosignGetProxyCookies", set_cosign_proxy_cookies,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "whether or not to get proxy cookies" ),

	AP_INIT_TAKE1( "CosignCookieExpireTime", set_cosign_expiretime,
	NULL, RSRC_CONF,
	"time (in seconds) after which we will issue a new service cookie" ),

	AP_INIT_FLAG( "CosignHttpOnlyCookies", set_cosign_httponly_cookies,
	NULL, RSRC_CONF | OR_AUTHCFG,
	"enable or disable \"httponly\" flag for Set-Cookie header" ),

#ifdef KRB
        AP_INIT_FLAG( "CosignGetKerberosTickets", set_cosign_tickets,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "whether or not to get kerberos tickets" ),
#ifdef GSS
        AP_INIT_FLAG( "CosignKerberosSetupGSS", set_cosign_gss,
        NULL, RSRC_CONF | ACCESS_CONF, 
        "whether or not to setup GSSAPI for k5" ),
#endif /* GSS */
#endif /* KRB */

        { NULL }
};

/* Apache 2.0-style hook registration */
    static void 
cosign_register_hooks( apr_pool_t *p )
{
#ifdef HAVE_MOD_AUTHZ_HOST
    static const char * const other_mods[] = { "mod_authz_host.c", NULL };
#else /* !HAVE_MOD_AUTHZ_HOST */
    static const char * const other_mods[] = { "mod_access.c", NULL };
#endif /* HAVE_MOD_AUTHZ_HOST */

    ap_hook_post_config( cosign_init, NULL, NULL, APR_HOOK_MIDDLE );
    ap_hook_handler( cosign_handler, NULL, NULL, APR_HOOK_MIDDLE );
    ap_hook_access_checker( cosign_auth, NULL, other_mods, APR_HOOK_MIDDLE );
    ap_hook_check_user_id( cosign_authn, NULL, NULL, APR_HOOK_MIDDLE );
}

/* Our actual module structure */
module AP_MODULE_DECLARE_DATA cosign_module =
{
    STANDARD20_MODULE_STUFF,		/* header */
    cosign_create_dir_config,		/* per-directory init */
    NULL,				/* per-directory merge */
    cosign_create_server_config,	/* per-server init */
    NULL,				/* per-server merge */
    cosign_cmds,			/* command handler */
    cosign_register_hooks		/* hook registration */
};

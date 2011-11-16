/*
 *  mod_cosign.c -- Apache sample cosign module
 */ 

#include "config.h"

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <ap_config.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <string.h>
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

module 		cosign_module;

    static void *
cosign_create_config( pool *p )
{
    cosign_host_config *cfg;

    cfg = (cosign_host_config *)ap_pcalloc( p, sizeof( cosign_host_config ));
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
cosign_create_dir_config( pool *p, char *path )
{
    return( cosign_create_config( p ));
}

    static void *
cosign_create_server_config( pool *p, server_rec *s )
{
    cosign_host_config	*cfg;

    cfg = cosign_create_config( p );

    /* assign a reasonable default CosignService */
    cfg->service = ap_psprintf( p, "cosign-%s", s->server_hostname );

    return( cfg );
}

    static void
cosign_init( server_rec *s, pool *p )
{
    extern char	*cosign_version;

    cosign_log( APLOG_NOTICE, s, "mod_cosign: version %s initialized.",
	    cosign_version );
    return;
}

    int
cosign_redirect( request_rec *r, cosign_host_config *cfg )
{
    char		*dest;
    char		*ref, *reqfact;
    int			i;
    unsigned int	port;

    /* if they've posted, let them know they are out of luck */
    if ( r->method_number == M_POST ) {
	dest = ap_psprintf( r->pool, "%s", cfg->posterror );
	ap_table_set( r->headers_out, "Location", dest );
	return( 0 );
    }

    /*
     * clear out Cache-Control and Expires headers, and preemptively set
     * Cache-Control header to keep aggressive caching configurations from
     * breaking cosign auth. if the browser caches the 302 redirect, the
     * redirect from the validation handler to the protected site will
     * result in the browser revisiting the weblogin server instead.
     */
    ap_table_unset( r->headers_out, "Cache-Control" );
    ap_table_unset( r->headers_out, "Expires" );

    ap_table_set( r->headers_out, "Cache-Control", "no-cache" );

    if ( cfg->siteentry != NULL && strcasecmp( cfg->siteentry, "none" ) != 0 ) {
	ref = cfg->siteentry;
    } else {
	/* live dangerously, we're redirecting to http */
	if ( cfg->http == 1 ) {
	    if ((( port = ap_get_server_port( r )) == 80 ) ||
		    ( cfg->noappendport == 1 )) {
		ref = ap_psprintf( r->pool, "http://%s%s", 
			ap_get_server_name( r ), r->unparsed_uri );
	    } else {
		ref = ap_psprintf( r->pool, "http://%s:%d%s", 
			ap_get_server_name( r ), port, r->unparsed_uri );
	    }
	/* live securely, redirecting to https */
	} else {
	    if ((( port = ap_get_server_port( r )) == 443 ) ||
		    ( cfg->noappendport == 1 )) {
		ref = ap_psprintf( r->pool, "https://%s%s", 
			ap_get_server_name( r ), r->unparsed_uri );
	    } else {
		ref = ap_psprintf( r->pool, "https://%s:%d%s", 
			ap_get_server_name( r ), port, r->unparsed_uri );
	    }
	}
    }

    if ( cfg->reqfc > 0 ) {
	reqfact = ap_pstrcat( r->pool, "factors=", cfg->reqfv[ 0 ], NULL );
	for ( i = 1; i < cfg->reqfc; i++ ) {
	    reqfact = ap_pstrcat( r->pool, reqfact, ",",
		    cfg->reqfv[ i ], NULL );
	}
	dest = ap_psprintf( r->pool,
		"%s?%s&%s&%s", cfg->redirect, reqfact, cfg->service, ref );
    } else {
	dest = ap_psprintf( r->pool,
		"%s?%s&%s", cfg->redirect, cfg->service, ref );
    }
    ap_table_set( r->headers_out, "Location", dest );
    return( 0 );
}

    static int
cosign_handler( request_rec *r )
{
    cosign_host_config	*cfg;
    ap_regmatch_t	matches[ 1 ];
    uri_components	uri;
    unsigned short	port;
    int			status;
    char		error[ 1024 ];
    const char		*qstr = NULL;
    const char		*pair;
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

    cfg = (cosign_host_config *)ap_get_module_config( r->server->module_config,							      &cosign_module );
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
	cosign_log( APLOG_ERR, r->server,
			"mod_cosign: no query string passed to handler." ); 
	return( HTTP_FORBIDDEN );
    }

    /* get cookie from query string */
    pair = ap_getword( r->pool, &qstr, '&' );
    if ( strncmp( pair, "cosign-", strlen( "cosign-" )) != 0 ) {
	( void )strtok((char *)pair, "=" );
	cosign_log( APLOG_NOTICE, r->server,
			"mod_cosign: invalid service \"%s\"", pair );
	goto validation_failed;
    }
    /* retain a copy of the complete string to use when we set the cookie */
    cookie = ap_pstrdup( r->pool, pair );

    /*
     * we don't need to check the service here. that check
     * is handled by cosignd when we check the service
     * cookie below. client's CN must match service name.
     */

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
    if (( status = ap_parse_uri_components( r->pool, dest, &uri )) != HTTP_OK) {
	cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: ap_parse_components %s failed", dest );
	return( HTTP_INTERNAL_SERVER_ERROR );
    }
    if ( uri.scheme == NULL || uri.hostname == NULL ) {
	cosign_log( APLOG_ERR, r->server,
		    "mod_cosign: bad destination URL: %s", dest );
	return( HTTP_BAD_REQUEST );
    }
    if ( uri.port == 0 ) {
	uri.port = ap_default_port_for_scheme( uri.scheme );
    }
    hostname = ap_get_server_name( r );
    port = ap_get_server_port( r );
    if ( strcasecmp( hostname, uri.hostname ) != 0 || 
		( port != uri.port && cfg->noappendport != 1 )) {
	if ( cfg->validredir == 1 ) {
	    if ( cfg->http == 1 ) {
		scheme == "http";
	    } else {
		scheme = "https";
	    }
	    if ( port != uri.port ) {
		dest = ap_psprintf( r->pool, "%s://%s:%d%s",
			    scheme, uri.hostname, uri.port, r->unparsed_uri );
	    } else {
		dest = ap_psprintf( r->pool, "%s://%s%s",
			    scheme, uri.hostname, r->unparsed_uri );
	    }
	    ap_table_set( r->headers_out, "Location", dest );

	    return( HTTP_MOVED_PERMANENTLY );
	} else {
	    cosign_log( APLOG_ERR, r->server,
			"mod_cosign: current hostname \"%s\" does not match "
			"service URL hostname \"%s\", cannot set cookie for "
			"correct host.", hostname, uri.hostname );

	    return( HTTP_SERVICE_UNAVAILABLE );
	}
    }

    cv = cosign_cookie_valid( cfg, cookie, &rekey, &si,
		r->connection->remote_ip, r->server );
    if ( rekey != NULL ) {
	/* we got a rekeyed cookie. let the request pool free it later. */
	ap_register_cleanup( r->pool, (void *)rekey, free, ap_null_cleanup );
	
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
	ap_table_set( r->headers_out, "Location", dest );
	return( HTTP_MOVED_PERMANENTLY );

    case COSIGN_OK:
	break;
    } 

    gettimeofday( &now, NULL );
    if ( strncmp( dest, "http://", strlen( "http://" )) == 0 ) {
	/* if we're redirecting to http, can set insecure cookie */
	full_cookie = ap_psprintf( r->pool, "%s/%lu; path=/",
				    cookie, now.tv_sec );
    } else {
	full_cookie = ap_psprintf( r->pool, "%s/%lu; path=/; secure",
				    cookie, now.tv_sec );
    }
    if ( cfg->httponly_cookies == 1 ) {
	full_cookie = ap_pstrcat( r->pool, full_cookie, "; httponly", NULL );
    }

    /* we get here, everything's OK. set cookie and redirect to dest. */
    ap_table_set( r->err_headers_out, "Set-Cookie", full_cookie );
    ap_table_set( r->headers_out, "Location", dest );

    return( HTTP_MOVED_PERMANENTLY );

validation_failed:
    ap_table_set( r->headers_out, "Location", cfg->referr );

    return( HTTP_MOVED_PERMANENTLY );
}

    static int
cosign_authn( request_rec *r )
{
    const char	*authn;
    cosign_host_config	*cfg;

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

    if ( ap_table_get( r->notes, "cosign-redirect" ) != NULL ) {
	if ( cosign_redirect( r, cfg ) != 0 ) {
	    return( HTTP_SERVICE_UNAVAILABLE );
	}
	return( HTTP_MOVED_TEMPORARILY );
    }

    if ( r->connection->user == NULL ) {
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
    char                *misc = NULL;
    char		*my_cookie;
    int			cv;
    int			cookietime = 0;
    struct sinfo	si;
    cosign_host_config	*cfg;
    struct timeval	now;
#ifdef GSS
    int			minor_status;
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
    if (( data = ap_table_get( r->headers_in, "Cookie" )) == NULL ) {
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
    my_cookie = ap_psprintf( r->pool, "%s=%s", cookiename, pair );

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
	return( HTTP_SERVICE_UNAVAILABLE );
    }

    /* Everything Shines, let them thru */
    if ( cv == COSIGN_OK ) {
	r->connection->user = ap_pstrcat( r->pool, si.si_user, NULL);
	r->connection->ap_auth_type = "Cosign";
	ap_table_set( r->subprocess_env, "COSIGN_SERVICE", cfg->service );
	ap_table_set( r->subprocess_env, "REMOTE_REALM", si.si_realm );
	ap_table_set( r->subprocess_env, "COSIGN_FACTOR", si.si_factor );

#ifdef KRB
	if ( cfg->krbtkt == 1 ) {
	    ap_table_set( r->subprocess_env, "KRB5CCNAME", si.si_krb5tkt );
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
    if ( cosign_redirect( r, cfg ) != 0 ) {
	return( HTTP_SERVICE_UNAVAILABLE );
    }
#endif /* notdef */
    if ( ap_some_auth_required( r )) {
	ap_table_setn( r->notes, "cosign-redirect", "true" );
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
    cosign_host_config		*cfg, *scfg;

    /*
     * apache's built-in (request time) merge is for directories only or
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
	cfg->siteentry = ap_pstrdup( params->pool, scfg->siteentry );
    }
    if ( cfg->reqfv == NULL ) {
	cfg->reqfv = scfg->reqfv; 
    }
    if ( cfg->reqfc == -1 ) {
	cfg->reqfc = scfg->reqfc; 
    }
    if ( cfg->suffix == NULL ) {
	cfg->suffix = ap_pstrdup( params->pool, scfg->suffix );
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

    cfg->filterdb = ap_pstrdup( params->pool, scfg->filterdb );
    cfg->hashlen =  scfg->hashlen;
    cfg->checkip =  scfg->checkip;
    cfg->proxydb = ap_pstrdup( params->pool, scfg->proxydb );
    cfg->tkt_prefix = ap_pstrdup( params->pool, scfg->tkt_prefix );

    if ( cfg->service == NULL ) {
	cfg->service = ap_pstrdup( params->pool, scfg->service );
    }
    if ( cfg->redirect == NULL ) {
	cfg->redirect = ap_pstrdup( params->pool, scfg->redirect );
    }
    if ( cfg->host == NULL ) {
	cfg->host = ap_pstrdup( params->pool, scfg->host );
    }
    if ( cfg->posterror == NULL ) {
	cfg->posterror = ap_pstrdup( params->pool, scfg->posterror );
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
set_cosign_post_error( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->posterror = ap_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_valid_reference( cmd_parms *params, void *mconfig, const char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->validref = ap_pstrdup( params->pool, arg );
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

    cfg->referr = ap_pstrdup( params->pool, arg );
    cfg->configured = 1;

    return( NULL );
}

    static const char *
set_cosign_service( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    if ( strncmp( arg, "cosign-", strlen( "cosign-" )) == 0 ) {
	cfg->service = ap_pstrdup( params->pool, arg );
    } else {
	cfg->service = ap_psprintf( params->pool, "cosign-%s", arg );
    }

    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_siteentry( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->siteentry = ap_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_checkip( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

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
set_cosign_factor( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;
    ACAV			*acav;
    int				ac, i;
    char			**av;

    cfg = cosign_merge_cfg( params, mconfig );

    if (( acav = acav_alloc()) == NULL ) {
	cosign_log( APLOG_ERR, params->server, "mod_cosign: set_cosign_factor:"
		" acav_alloc failed" );
	exit( 1 );
    }

    if (( ac = acav_parse( acav, arg, &av )) < 0 ) {
	cosign_log( APLOG_ERR, params->server, "mod_cosign: set_cosign_factor:"
		" acav_parse failed" );
	exit( 1 );
    }

    /* should null terminate av */
    cfg->reqfv = ap_palloc( params->pool, ac * sizeof( char * ));
    for ( i = 0; i < ac; i++ ) {
	cfg->reqfv[ i ] = ap_pstrdup( params->pool, av[ i ] );
    }
    cfg->reqfc = ac;

    acav_free( acav );

    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_factorsuffix( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->suffix = ap_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_ignoresuffix( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->fake = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_public( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->public = flag;
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_port( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;
    struct connlist		*cur;
    unsigned short		portarg;

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
set_cosign_redirect( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->redirect = ap_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_filterdb( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignFilterDB not valid per dir!" );
    }

    cfg->filterdb = ap_pstrdup( params->pool, arg );
    return( NULL );
}

    static const char *
set_cosign_hashlen( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

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
set_cosign_proxydb( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignProxyDB not valid per dir!" );
    }

    cfg->proxydb = ap_pstrdup( params->pool, arg );
    return( NULL );
}

    static const char *
set_cosign_tkt_prefix( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignTicketPrefix not valid per dir!" );
    }

    cfg->tkt_prefix = ap_pstrdup( params->pool, arg );
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
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->proxy = flag; 
    cfg->configured = 1; 
    return( NULL );
}

    static const char *
set_cosign_certs( cmd_parms *params, void *mconfig,
	char *one, char *two, char *three)
{
    cosign_host_config		*cfg;
    struct stat			st;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->key = ap_pstrdup( params->pool, one );
    cfg->cert = ap_pstrdup( params->pool, two );
    cfg->cadir = ap_pstrdup( params->pool, three );

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

    if ( access( cfg->cadir, R_OK | X_OK ) != 0 ) {
	return( "An error occured reading the CADir." );
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
set_cosign_host( cmd_parms *params, void *mconfig, char *arg )
{
    struct hostent		*he;
    int				i;
    struct connlist		*new, **cur;
    char			*err;
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->host = ap_pstrdup( params->pool, arg );
    if (( he = ap_pgethostbyname( params->pool, cfg->host )) == NULL ) {
	err = ap_psprintf( params->pool, "%s: host unknown", cfg->host );
	return( err );
    }

    /* This is hairy. During operation, we re-order the connection list
     * so that the most responsive server is at the head of the list.
     * This requires updates to the pointer to the list head from the cfg
     * structure. However, the cfg structure gets copied around when
     * Apache does configuration merges, so there isn't a single cfg
     * structure in any one process. Instead, we point to a pointer
     * to the list head. */
    cfg->cl = (struct connlist **)
		ap_palloc(params->pool, sizeof(struct connlist *));

    /* preserve address order as returned from DNS */
    /* actually, here we will randomize for "load balancing" */
    cur = cfg->cl;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	new = ( struct connlist * )
		ap_palloc( params->pool, sizeof( struct connlist ));
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
    cfg->configured = 1; 
    return( NULL );
}

    static const char *
set_cosign_http( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->http = flag; 
    cfg->configured = 1; 
    return( NULL );
}

    static const char *
set_cosign_noappendport( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->noappendport = flag; 
    cfg->configured = 1; 
    return( NULL );
}

    static const char *
set_cosign_expiretime( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

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

    static void
cosign_child_cleanup( server_rec *s, pool *p )
{
    cosign_host_config	*cfg;

    /* upon child exit, close all open SNETs */
    cfg = (cosign_host_config *) ap_get_module_config( s->module_config,
	    &cosign_module );
    if ( teardown_conn( cfg->cl, s ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: teardown conn err" );
    }
}

static command_rec cosign_cmds[ ] =
{
        { "CosignPostErrorRedirect", set_cosign_post_error,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the URL to deliver bad news about POSTed data" },

        { "CosignService", set_cosign_service,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the name of the cosign service" },

        { "CosignProtected", set_cosign_protect,
        NULL, RSRC_CONF | OR_AUTHCFG, FLAG,
        "turn cosign off on a location or directory basis" },

        { "CosignRedirect", set_cosign_redirect,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the URL to register service cookies with cosign" },

        { "CosignValidReference", set_cosign_valid_reference,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the regular expression matching valid redirect service URLs" },

	{ "CosignAllowValidationRedirect",
	set_cosign_allow_validation_redirect, NULL,
	RSRC_CONF | ACCESS_CONF, FLAG,
	"allow redirection to different validdation URL if "
	"current vhost does not match service URL hostname AND "
	"service URL matches CosignValidReferences pattern" },

        { "CosignValidationErrorRedirect",
	set_cosign_validation_error_redirect,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "where the location handler sends us in case of a bad destination" },

        { "CosignPort", set_cosign_port,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the port to register service cookies with cosign" },

        { "CosignHostname", set_cosign_host,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the name of the cosign hosts(s)" },

        { "CosignFilterDB", set_cosign_filterdb,
        NULL, RSRC_CONF, TAKE1,
        "the path to the cosign filter DB" },

        { "CosignFilterHashLength", set_cosign_hashlen,
        NULL, RSRC_CONF, TAKE1,
        "0, 1, or 2 - if you want the filter db stored in subdirs" },

        { "CosignProxyDB", set_cosign_proxydb,
        NULL, RSRC_CONF, TAKE1,
        "the path to the cosign proxy DB" },

        { "CosignTicketPrefix", set_cosign_tkt_prefix,
        NULL, RSRC_CONF, TAKE1,
        "the path to the cosign Kerberos ticket directory" },

	{ "CosignCheckIP", set_cosign_checkip,
	NULL, RSRC_CONF, TAKE1,
	"\"never\", \"initial\", or \"always\"" },

	{ "CosignSiteEntry", set_cosign_siteentry,
	NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
	"\"none\" or URL to redirect for users who successfully authenticate" },

	{ "CosignRequireFactor", set_cosign_factor,
	NULL, RSRC_CONF | OR_AUTHCFG, RAW_ARGS,
	"the authentication factors that must be satisfied" },

	{ "CosignFactorSuffix", set_cosign_factorsuffix,
	NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
	"the factor suffix when testing for compliance" },

	{ "CosignFactorSuffixIgnore", set_cosign_ignoresuffix,
	NULL, RSRC_CONF | ACCESS_CONF, FLAG,
	"on or off, on allows you to accept faux factors, off denies access" },

	{ "CosignAllowPublicAccess", set_cosign_public,
	NULL, RSRC_CONF | OR_AUTHCFG, FLAG,
	"make authentication optional for protected sites" },

        { "CosignHttpOnly", set_cosign_http,
        NULL, RSRC_CONF | ACCESS_CONF, FLAG,
        "redirect to http instead of https on the local server" },

        { "CosignNoAppendRedirectPort", set_cosign_noappendport,
        NULL, RSRC_CONF | ACCESS_CONF, FLAG,
        "for SSL load balancers - redirect with no added port to the URL" },

        { "CosignCrypto", set_cosign_certs,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE3,
        "crypto for use in talking to cosign host" },

        { "CosignGetProxyCookies", set_cosign_proxy_cookies,
        NULL, RSRC_CONF | ACCESS_CONF, FLAG,
        "whether or not to get proxy cookies" },

	{ "CosignCookieExpireTime", set_cosign_expiretime,
	NULL, RSRC_CONF, TAKE1,
	"time (in seconds) after which we will issue a new service cookie" },

	{ "CosignHttpOnlyCookies", set_cosign_httponly_cookies,
	NULL, RSRC_CONF | OR_AUTHCFG, FLAG,
	"enable or disable \"httponly\" flag for Set-Cookie header" },

#ifdef KRB
        { "CosignGetKerberosTickets", set_cosign_tickets,
        NULL, RSRC_CONF | ACCESS_CONF, FLAG,
        "whether or not to get kerberos tickets" },
#ifdef GSS
        { "CosignKerberosSetupGSS", set_cosign_gss,
        NULL, RSRC_CONF | ACCESS_CONF, FLAG,
        "whether or not to setup GSSAPI for k5" },
#endif /* GSS */
#endif /* KRB */

        { NULL }
};

static const handler_rec cosign_handlers[] = {
    { "cosign", cosign_handler },

    { NULL }
};

module MODULE_VAR_EXPORT cosign_module = {
    STANDARD_MODULE_STUFF, 
    cosign_init,	    /* module initializer                 */
    cosign_create_dir_config, /* create per-dir config structures */
    NULL,                  /* merge per-dir config structures     */
    cosign_create_server_config, /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    cosign_cmds,           /* table of config file commands       */
    cosign_handlers,       /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    cosign_authn,          /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    cosign_auth,           /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,	   	   /* [#7] pre-run fixups                 */
    NULL,  	  	   /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    NULL,                  /* child_init                          */
    NULL,                  /* child_exit                          */
    NULL                   /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                  /* EAPI: add_module                    */
    NULL,                  /* EAPI: remove_module                 */
    NULL,                  /* EAPI: rewrite_command               */
    NULL                   /* EAPI: new_connection                */
#endif
};

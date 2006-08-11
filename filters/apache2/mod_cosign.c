/*
 *  mod_cosign.c -- Apache sample cosign module
 */ 

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
#include "log.h"

static int	set_cookie_and_redirect( request_rec *, cosign_host_config * );
extern int      cosign_protocol;

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
    cfg->port = 0;
    cfg->protect = -1;
    cfg->configured = 0;
    cfg->checkip = IPCHECK_INITIAL;
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
    return( cosign_create_config( p ));
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
set_cookie_and_redirect( request_rec *r, cosign_host_config *cfg )
{
    char		*dest, *my_cookie;
    char                *full_cookie, *ref, *reqfact;
    char		cookiebuf[ 128 ];
    int                 i;
    unsigned int	port;
    struct timeval      now;

    /* if they've posted, let them know they are out of luck */
    if ( r->method_number == M_POST ) {
	dest = apr_psprintf( r->pool, "%s", cfg->posterror );
	apr_table_set( r->headers_out, "Location", dest );
	return( 0 );
    }

    if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
	cosign_log( APLOG_ERR, r->server,
		"mod_cosign: Raisins! Something wrong with mkcookie()" );
	return( -1 );
    }

    my_cookie = apr_psprintf( r->pool, "%s=%s", cfg->service, cookiebuf );

    /* older version of IE on MacOS 9 seem to need ";;" instead of */
    /* simply ";" as the cookie delimiter, otherwise no cookie is */
    /* returned upon revisit. */

    gettimeofday( &now, NULL );
    if ( cfg->http == 1 ) { /* living dangerously */
	full_cookie = apr_psprintf( r->pool, "%s/%lu;;path=/",
		my_cookie, now.tv_sec );
    } else {
	full_cookie = apr_psprintf( r->pool, "%s/%lu;;path=/;secure", 
		my_cookie, now.tv_sec );
    }

    /* cookie needs to be set and sent in error headers as 
     * standard headers don't get returned when we redirect,
     * and we need to do both here. 
     */

    apr_table_set( r->err_headers_out, "Set-Cookie", full_cookie );

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

    /* we need to remove this semi-colon eventually */
    if ( cfg->reqfc > 0 ) {
        reqfact = apr_pstrcat( r->pool, "factors=", cfg->reqfv[ 0 ], NULL );
        for ( i = 1; i < cfg->reqfc; i++ ) {
            reqfact = apr_pstrcat( r->pool, reqfact, ",",
                    cfg->reqfv[ i ], NULL );
        }
        dest = apr_psprintf( r->pool,
                "%s?%s&%s&%s", cfg->redirect, reqfact, my_cookie, ref );
    } else {
        /* we need to remove this semi-colon eventually */
        dest = apr_psprintf( r->pool,
                "%s?%s;&%s", cfg->redirect, my_cookie, ref );
    }
    apr_table_set( r->headers_out, "Location", dest );
    return( 0 );
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
        if ( set_cookie_and_redirect( r, cfg ) != 0 ) {
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

    /*
     * Look for cfg->service cookie. if there isn't one,
     * set it and redirect.
     */

    if (( data = apr_table_get( r->headers_in, "Cookie" )) == NULL ) {
	goto set_cookie;
    }

    while ( *data && ( pair = ap_getword( r->pool, &data, ';' ))) {
	cookiename = ap_getword( r->pool, &pair, '=' );
	if ( strcasecmp( cookiename, cfg->service ) == 0 ) {
	    break;
	}
	cookiename = NULL;
	while ( *data == ' ' ) { data++; }
    }

    /* the length of the cookie payload is determined by our call to
     * mkcookie() in set_cookie_and_redirect(). technically
     * unecessary since invalid short cookies won't be registered
     * anyway, however, adding this check prevents an unknown
     * cookie failover condition if the browser doesn't honor expiration
     * dates on cookies.
     */
     
    if (( cookiename == NULL ) || ( strlen( pair ) < 120 )) {
	goto set_cookie;
    }
    my_cookie = apr_psprintf( r->pool, "%s=%s", cookiename, pair );

    /* if it's a stale cookie, give out a new one */
    gettimeofday( &now, NULL );
    (void)strtok( my_cookie, "/" );
    if (( misc = strtok( NULL, "/" )) != NULL ) {
        cookietime = atoi( misc );
    }
    if (( cookietime > 0 ) && ( now.tv_sec - cookietime ) > cfg->expiretime ) {
        goto set_cookie;
    }

    /*
     * Validate cookie with backside server.  If we already have a cached
     * version of the data, just verify the cookie's still valid.
     * Otherwise, retrieve the auth info from the server.
     */
    cv = cosign_cookie_valid( cfg, my_cookie, &si, r->connection->remote_ip,
	    r->server );
    if ( cv == COSIGN_ERROR ) {
	return( HTTP_SERVICE_UNAVAILABLE );	/* it's all forbidden! */
    } 

    /* Everything Shines, let them thru */
    if ( cv == COSIGN_OK ) {
	r->user = apr_pstrcat( r->pool, si.si_user, NULL);
	r->ap_auth_type = "Cosign";
	apr_table_set( r->subprocess_env, "COSIGN_SERVICE", cfg->service );
	apr_table_set( r->subprocess_env, "REMOTE_REALM", si.si_realm );
	if ( cosign_protocol == 2 ) {
	    apr_table_set( r->subprocess_env, "COSIGN_FACTOR", si.si_factor );
        }
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

set_cookie:
    /* let them thru regardless if this is "public" */
    if ( cfg->public == 1 ) {
        return( DECLINED );
    }
    if ( set_cookie_and_redirect( r, cfg ) != 0 ) {
        return( HTTP_SERVICE_UNAVAILABLE );
    }
    if ( ap_some_auth_required( r )) {
        apr_table_setn( r->notes, "cosign-redirect", "true" );
        return( DECLINED );
    } else {
        if ( set_cookie_and_redirect( r, cfg ) != 0 ) {
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
set_cosign_post_error( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->posterror = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_service( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->service = apr_psprintf( params->pool,"cosign-%s", arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_siteentry( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->siteentry = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_checkip( cmd_parms *params, void *mconfig, char *arg )
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
set_cosign_factor( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config          *cfg;
    ACAV                        *acav;
    int                         ac, i;
    char                        **av;

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
set_cosign_factorsuffix( cmd_parms *params, void *mconfig, char *arg )
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
set_cosign_port( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config  *cfg;
    int			 portarg;
    struct connlist	 *cur;

    cfg = cosign_merge_cfg( params, mconfig );

    portarg = strtol( arg, (char **)NULL, 10 );
    cfg->port = htons( portarg );

    for ( cur = cfg->cl; cur != NULL; cur = cur->conn_next ) {
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
    cosign_host_config          *cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->redirect = apr_pstrdup( params->pool, arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_filterdb( cmd_parms *params, void *mconfig, char *arg )
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
set_cosign_hashlen( cmd_parms *params, void *mconfig, char *arg )
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
set_cosign_proxydb( cmd_parms *params, void *mconfig, char *arg )
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
set_cosign_tkt_prefix( cmd_parms *params, void *mconfig, char *arg )
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
	char *one, char *two, char *three)
{
    cosign_host_config		*cfg;

    cfg = cosign_merge_cfg( params, mconfig );

    cfg->key = apr_pstrdup( params->pool, one );
    cfg->cert = apr_pstrdup( params->pool, two );
    cfg->cadir = apr_pstrdup( params->pool, three );

    if (( cfg->key == NULL ) || ( cfg->cert == NULL ) ||
	    ( cfg->cadir == NULL)) {
	return( "You know you want the crypto!" );
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
    if ( SSL_CTX_load_verify_locations( cfg->ctx, NULL, cfg->cadir ) != 1 ) {
	cosign_log( APLOG_ERR, params->server,
		"SSL_CTX_load_verify_locations: %s: %s\n",
		cfg->key, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    SSL_CTX_set_verify( cfg->ctx, SSL_VERIFY_PEER, NULL );

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

    cfg->host = apr_pstrdup( params->pool, arg );
    if (( he = gethostbyname( cfg->host )) == NULL ) {
	err = apr_psprintf( params->pool, "%s: host unknown", cfg->host );
	return( err );
    }

    /* preserve address order as returned from DNS */
    /* actually, here we will randomize for "load balancing" */
    cur = &cfg->cl;
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
set_cosign_expiretime( cmd_parms *params, void *mconfig, char *arg )
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
        NULL, RSRC_CONF | ACCESS_CONF, 
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
    static const char * const other_mods[] = { "mod_access.c", NULL };

    ap_hook_post_config( cosign_init, NULL, NULL, APR_HOOK_MIDDLE );
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

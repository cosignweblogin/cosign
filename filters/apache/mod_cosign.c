/*
 *  mod_cosign.c -- Apache sample cosign module
 */ 

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#ifdef KRB
#ifdef GSS
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif /* GSS */
#ifdef KRB4
#include <kerberosIV/krb.h>
#endif /* KRB4 */
#endif /* KRB */

#include <openssl/ssl.h>
#include <openssl/err.h>


#include <snet.h>

#include "sparse.h"
#include "mkcookie.h"
#include "cosign.h"

static int	set_cookie_and_redirect( request_rec *, cosign_host_config * );

module cosign_module;

    static void *
cosign_create_dir_config( pool *p, char *path )
{
    cosign_host_config *cfg;
    
    cfg = (cosign_host_config *)ap_pcalloc( p, sizeof( cosign_host_config ));
    cfg->service = NULL;
    cfg->redirect = NULL;
    cfg->posterror = NULL;
    cfg->port = htons( 6663 );
    cfg->protect = 1;
    cfg->configured = 0;
    cfg->cl = NULL;
    cfg->ctx = NULL;
    cfg->key = NULL;
    cfg->cert = NULL;
    cfg->cadir = NULL;
    cfg->http = 0;
#ifdef KRB
    cfg->krbtkt = 0;
#ifdef GSS
    cfg->gss = 0;
#endif /* GSS */
#ifdef KRB4
    cfg->krb524 = 0;
#endif /* KRB4 */
#endif /* KRB */
    return( cfg );

}

    static void *
cosign_create_server_config( pool *p, server_rec *s )
{
    cosign_host_config *cfg;
    
    cfg = (cosign_host_config *)ap_pcalloc( p, sizeof( cosign_host_config ));
    cfg->host = NULL;
    cfg->service = NULL;
    cfg->redirect = NULL;
    cfg->posterror = NULL;
    cfg->port = htons( 6663 );
    cfg->protect = 1;
    cfg->configured = 0;
    cfg->cl = NULL;
    cfg->ctx = NULL;
    cfg->key = NULL;
    cfg->cert = NULL;
    cfg->cadir = NULL;
    cfg->http = 0;
#ifdef KRB
    cfg->krbtkt = 0;
#ifdef GSS
    cfg->gss = 0;
#endif /* GSS */
#ifdef KRB4
    cfg->krb524 = 0;
#endif /* KRB4 */
#endif /* KRB */
    return( cfg );
}

    static void
cosign_init( server_rec *s, pool *p )
{
    extern char	*cosign_version;

    ap_log_error( APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, s,
	    "mod_cosign: version %s initialized.", cosign_version );

    return;
}

    int
set_cookie_and_redirect( request_rec *r, cosign_host_config *cfg )
{
    char		*dest, *my_cookie, *full_cookie, *ref;
    char		cookiebuf[ 128 ];
    unsigned int	port;

    if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
		"mod_cosign: Raisins! Something wrong with mkcookie()" );
	return( -1 );
    }

    if ( r->method_number == M_POST ) {
	my_cookie = ap_psprintf( r->pool,
		"%s=%s;", cfg->posterror, cookiebuf );
    } else {
	my_cookie = ap_psprintf( r->pool,
		"%s=%s;", cfg->service, cookiebuf );
    }

    if ( cfg->http ) { /* living dangerously */
	full_cookie = ap_psprintf( r->pool, "%s;path=/", my_cookie );
    } else {
	full_cookie = ap_psprintf( r->pool, "%s;path=/;secure", my_cookie );
    }

    /* cookie needs to be set and sent in error headers as 
     * standard headers don't get returned when we redirect,
     * and we need to do both here. 
     */

    ap_table_set( r->err_headers_out, "Set-Cookie", full_cookie );

    /* live dangerously, we're redirecting to http */
    if ( cfg->http ) {
	if (( port = ap_get_server_port( r )) == 80 ) {
	    ref = ap_psprintf( r->pool, "http://%s%s", 
		    ap_get_server_name( r ), r->unparsed_uri );
	} else {
	    ref = ap_psprintf( r->pool, "http://%s:%d%s", 
		    ap_get_server_name( r ), port, r->unparsed_uri );
	}
    /* live securely, redirecting to https */
    } else {
	if (( port = ap_get_server_port( r )) == 443 ) {
	    ref = ap_psprintf( r->pool, "https://%s%s", 
		    ap_get_server_name( r ), r->unparsed_uri );
	} else {
	    ref = ap_psprintf( r->pool, "https://%s:%d%s", 
		    ap_get_server_name( r ), port, r->unparsed_uri );
	}
    }

    dest = ap_psprintf( r->pool, "%s?%s&%s", cfg->redirect, my_cookie, ref );
    ap_table_set( r->headers_out, "Location", dest );
    return( 0 );
}

    static int
cosign_authn( request_rec *r )
{
    const char *authn;

    if ((( authn = ap_auth_type( r )) == NULL ) || 
	    ( r->connection->user == NULL )) {
	return( DECLINED );
    }

    if ( strcmp( authn, "Cosign" ) != 0 ) {
	return( DECLINED );
    } 
    return( OK );
}


    static int
cosign_auth( request_rec *r )
{
    const char		*cookiename = NULL;
    const char		*data = NULL, *pair = NULL;
    char		*my_cookie;
    int			cv;
    struct sinfo	si;
    cosign_host_config	*cfg;
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

    if ( !cfg->configured || !cfg->protect ) {
	return( DECLINED );
    }

    /*
     * Verify cfg has been setup correctly by admin
     */

    if (( cfg->host == NULL ) || ( cfg->redirect == NULL ) ||
		( cfg->service == NULL || cfg->posterror == NULL )) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
		"mod_cosign: Cosign is not configured correctly:" );
	if ( cfg->host == NULL ) {
	    ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
		    "mod_cosign: CosignHostname not set." );
	}
	if ( cfg->redirect == NULL ) {
	    ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
		    "mod_cosign: CosignRedirect not set." );
	}
	if ( cfg->service == NULL ) {
	    ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
		    "mod_cosign: CosignService not set." );
	}
	if ( cfg->posterror == NULL ) {
	    ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, r->server,
		    "mod_cosign: CosignPostErrorRedirect not set." );
	}
	return( HTTP_SERVICE_UNAVAILABLE );
    }

    /*
     * Look for cfg->service cookie. if there isn't one,
     * set it and redirect.
     */

    if (( data = ap_table_get( r->headers_in, "Cookie" )) == NULL ) {
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

    /*
     * Validate cookie with backside server.  If we already have a cached
     * version of the data, just verify the cookie's still valid.
     * Otherwise, retrieve the auth info from the server.
     */
    my_cookie = ap_psprintf( r->pool, "%s=%s", cookiename, pair );
    if (( cv = cosign_cookie_valid( cfg, my_cookie, &si,
	    r->connection->remote_ip )) < 0 ) {	
	return( HTTP_SERVICE_UNAVAILABLE );	/* it's all forbidden! */
    } 

    /* Everything Shines, let them thru */
    if ( cv == 0 ) {
	r->connection->user = ap_pstrcat( r->pool, si.si_user, NULL);
	r->connection->ap_auth_type = "Cosign";
	ap_table_set( r->subprocess_env, "COSIGN_SERVICE", cfg->service );
	ap_table_set( r->subprocess_env, "REMOTE_REALM", si.si_realm );
#ifdef KRB
	if ( cfg->krbtkt ) {
	    ap_table_set( r->subprocess_env, "KRB5CCNAME", si.si_krb5tkt );
#ifdef GSS
	if ( cfg->gss ) {
	    if ( gss_krb5_ccache_name( &minor_status, si.si_krb5tkt, NULL )
		    != GSS_S_COMPLETE ) {
		ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO,
			 r->server, "mod_cosign: gss_krb5_ccache_name" );
	    }
	}
#endif /* GSS */
#ifdef KRB4
	if ( cfg->krb524 ) {
	    ap_table_set( r->subprocess_env, "KRBTKFILE", si.si_krb4tkt );
	    krb_set_tkt_string( si.si_krb4tkt );
	}
#endif /* KRB4 */
	}
#endif /* KRB */
	return( DECLINED );
    }

set_cookie:
    if ( set_cookie_and_redirect( r, cfg ) != 0 ) {
	return( HTTP_SERVICE_UNAVAILABLE );
    }
    return( HTTP_MOVED_TEMPORARILY );
}

    static const char *
set_cosign_protect( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg, *scfg;

    scfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    if ( params->path == NULL ) {
	cfg = scfg;
    } else {
	cfg = (cosign_host_config *)mconfig;
	cfg->redirect = ap_pstrdup( params->pool, scfg->redirect );
	cfg->posterror = ap_pstrdup( params->pool, scfg->posterror );
	cfg->host = ap_pstrdup( params->pool, scfg->host );
	cfg->cl = scfg->cl;
	cfg->port = scfg->port; 
	cfg->ctx = scfg->ctx;
	if ( cfg->service == NULL ) {
	    cfg->service = ap_pstrdup( params->pool, scfg->service );
	}
#ifdef KRB
	cfg->krbtkt = scfg->krbtkt; 
#ifdef GSS
	cfg->gss = scfg->gss;
#endif /* GSS */
#ifdef KRB4
	cfg->krb524 = scfg->krb524;
#endif /* KRB4 */
#endif /* KRB */

    }

    cfg->protect = flag; 
    cfg->configured = 1; 
    return( NULL );
}

    static const char *
set_cosign_post_error( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignPostErrorRedirect not valid per dir!" );
    }

    if ( cfg->posterror != NULL ) {
	return( "Only one Error Redirecion URL per configuration allowed." );
    }

    cfg->posterror = ap_pstrdup( params->pool, arg );
    return( NULL );
}

        static const char *
set_cosign_service( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg, *scfg;

    scfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    if ( params->path == NULL ) {
	cfg = scfg;
    } else {
	cfg = (cosign_host_config *)mconfig;
	cfg->redirect = ap_pstrdup( params->pool, scfg->redirect );
	cfg->posterror = ap_pstrdup( params->pool, scfg->posterror );
	cfg->host = ap_pstrdup( params->pool, scfg->host );
	cfg->cl = scfg->cl;
	cfg->port = scfg->port; 
	cfg->ctx = scfg->ctx;
#ifdef KRB
	cfg->krbtkt = scfg->krbtkt; 
#ifdef GSS
	cfg->gss = scfg->gss;
#endif /* GSS */
#ifdef KRB4
	cfg->krb524 = scfg->krb524;
#endif /* KRB4 */
#endif /* KRB */
    }

    cfg->service = ap_psprintf( params->pool,"cosign-%s", arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_port( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;
    struct connlist		*cur;
    unsigned short		portarg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignPort not valid per dir!" );
    }

    portarg = strtol( arg, (char **)NULL, 10 );
    cfg->port = htons( portarg );

    for ( cur = cfg->cl; cur != NULL; cur = cur->conn_next ) {
	cur->conn_sin.sin_port = cfg->port;
    }
    return( NULL );
}

    static const char *
set_cosign_redirect( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignRedirect not valid per dir!" );
    }

    if ( cfg->redirect != NULL ) {
	return( "Only one redirect per configuration allowed." );
    }

    cfg->redirect = ap_pstrdup( params->pool, arg );
    return( NULL );
}

#ifdef KRB
#ifdef KRB4
    static const char *
krb524_cosign_tickets( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "Ticket conversion policy to be set on a per host basis." );
    }

    cfg->krb524 = flag; 
    cfg->configured = 1; 
    return( NULL );
}
#endif /* KRB4 */

#ifdef GSS
    static const char *
set_cosign_gss( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "GSS setup policy needs to be set on a per host basis." );
    }

    cfg->gss = flag; 
    cfg->configured = 1; 
    return( NULL );
}
#endif /* GSS */

    static const char *
set_cosign_tickets( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "Kerberos ticket policy needs to be set on a per host basis." );
    }

    cfg->krbtkt = flag; 
    cfg->configured = 1; 
    return( NULL );
}
#endif /* KRB */

    static const char *
set_cosign_certs( cmd_parms *params, void *mconfig,
	char *one, char *two, char *three)
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "Certificates need to be set on a per host basis." );
    }

    cfg->key = ap_pstrdup( params->pool, one );
    cfg->cert = ap_pstrdup( params->pool, two );
    cfg->cadir = ap_pstrdup( params->pool, three );

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
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, params->server,
		"SSL_CTX_new: %s\n", ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_use_PrivateKey_file( cfg->ctx,
	    cfg->key, SSL_FILETYPE_PEM ) != 1 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, params->server,
		"SSL_CTX_use_PrivateKey_file: %s: %s\n",
		cfg->key, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( cfg->ctx, cfg->cert ) != 1 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, params->server,
		"SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cfg->cert, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_check_private_key( cfg->ctx ) != 1 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, params->server,
		"SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_load_verify_locations( cfg->ctx, NULL, cfg->cadir ) != 1 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, params->server,
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

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignHostname not valid per dir!" );
    }

    if ( cfg->host != NULL ) {
	return( "There can be only one host per configuration!" );
    }

    cfg->host = ap_pstrdup( params->pool, arg );
    if (( he = ap_pgethostbyname( params->pool, cfg->host )) == NULL ) {
	err = ap_psprintf( params->pool, "%s: host unknown", cfg->host );
	return( err );
    }

    /* preserve address order as returned from DNS */
    /* actually, here we will randomize for "load balancing" */
    cur = &cfg->cl;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	new = ( struct connlist * )
		ap_palloc( params->pool, sizeof( struct connlist ));
	memset( &new->conn_sin, 0, sizeof( struct sockaddr_in ));
	new->conn_sin.sin_family = AF_INET;
	new->conn_sin.sin_port = cfg->port;
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
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "If you want to run Cosign using http, you must do it this way for the whole server.");
    }

    cfg->http = flag; 
    cfg->configured = 1; 
    return( NULL );
}

    static void
cosign_child_cleanup( server_rec *s, pool *p )
{
    cosign_host_config	*cfg;

    /* upon child exit, close all open SNETs */
    cfg = (cosign_host_config *) ap_get_module_config( s->module_config,
	    &cosign_module );
    if ( teardown_conn( cfg->cl ) != 0 ) {
	ap_log_error( APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, s,
		"mod_cosign: teardown conn err" );
    }
    return;
}

static command_rec cosign_cmds[ ] =
{
        { "CosignPostErrorRedirect", set_cosign_post_error,
        NULL, RSRC_CONF, TAKE1,
        "the URL to deliver bad news about POSTed data" },

        { "CosignService", set_cosign_service,
        NULL, RSRC_CONF | ACCESS_CONF, TAKE1,
        "the name of the cosign service" },

        { "CosignProtected", set_cosign_protect,
        NULL, RSRC_CONF | ACCESS_CONF, FLAG,
        "turn cosign off on a location or directory basis" },

        { "CosignRedirect", set_cosign_redirect,
        NULL, RSRC_CONF, TAKE1,
        "the URL to register service cookies with cosign" },

        { "CosignPort", set_cosign_port,
        NULL, RSRC_CONF, TAKE1,
        "the port to register service cookies with cosign" },

        { "CosignHostname", set_cosign_host,
        NULL, RSRC_CONF, TAKE1,
        "the name of the cosign hosts(s)" },

        { "CosignHttpOnly", set_cosign_http,
        NULL, RSRC_CONF, FLAG,
        "redirect to http instead of https on the local server" },

        { "CosignCrypto", set_cosign_certs,
        NULL, RSRC_CONF, TAKE3,
        "crypto for use in talking to cosign host" },
#ifdef KRB
        { "CosignGetKerberosTickets", set_cosign_tickets,
        NULL, RSRC_CONF, FLAG,
        "whether or not to get kerberos tickets" },
#ifdef GSS
        { "CosignKerberosSetupGSS", set_cosign_gss,
        NULL, RSRC_CONF, FLAG,
        "whether or not to setup GSSAPI for k5" },
#endif /* GSS */
#ifdef KRB4
        { "CosignKerberos524", krb524_cosign_tickets,
        NULL, RSRC_CONF, FLAG,
        "whether or not to convert kerberos 5 tickets to k4" },
#endif /* KRB4 */
#endif /* KRB */

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
    NULL,		   /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    cosign_authn,          /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    cosign_auth,           /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,	  	   /* [#7] pre-run fixups                 */
    NULL,  	  	   /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    NULL,                  /* child_init                          */
    cosign_child_cleanup,  /* child_exit                          */
    NULL                   /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                  /* EAPI: add_module                    */
    NULL,                  /* EAPI: remove_module                 */
    NULL,                  /* EAPI: rewrite_command               */
    NULL                   /* EAPI: new_connection                */
#endif
};

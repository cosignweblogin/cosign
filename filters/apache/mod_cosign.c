/*
 *  mod_cosign.c -- Apache sample cosign module
 */ 

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include <snet.h>
#include <string.h>

#include "sparse.h"
#include "cosign.h"

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
    cfg->sl = NULL;
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
    cfg->sl = NULL;
    return( cfg );
}
    int
set_cookie_and_redirect( request_rec *r, cosign_host_config *cfg )
{
    char		*dest;
    char		*my_cookie;
    char		cookiebuf[ 128 ];

    if ( mkcookie( sizeof( cookiebuf ), cookiebuf ) != 0 ) {
	fprintf( stderr, "Raisins! Something wrong with your cookie!\n" );
	return( -1 );
    }

    if ( r->method_number == M_POST ) {
	my_cookie = ap_psprintf( r->pool,
		"%s=%s;path=/;", cfg->posterror, cookiebuf );
    } else {
	my_cookie = ap_psprintf( r->pool,
		"%s=%s;path=/;", cfg->service, cookiebuf );
    }

    /* cookie needs to be set and sent in error headers as 
     * standard headers don't get returned when we redirect,
     * and we need to do both here. 
     */

    ap_table_set( r->err_headers_out, "Set-Cookie", my_cookie );
    ap_table_set( r->headers_out,
	    "Expires", "Thurs, 27 Jan 1977 21:20:00 GMT" );
    dest = ap_psprintf( r->pool, "%s?%s", cfg->redirect, my_cookie );
    ap_table_set( r->headers_out, "Location", dest );
    return( 0 );
}

    static int
cosign_auth( request_rec *r )
{
    const char		*cookiename = NULL;
    const char		*data = NULL, *pair = NULL;
    char		*my_cookie;
    struct sinfo	si;
    cosign_host_config	*cfg;

    /*
     * Select the correct cfg
     */
    cfg = (cosign_host_config *)ap_get_module_config(
	    r->per_dir_config, &cosign_module);
    if ( !cfg->configured ) {
	cfg = (cosign_host_config *)ap_get_module_config(
		r->server->module_config, &cosign_module);
    }

    /*
     * Verify cfg has been setup correctly by admin
     */

    if ( !cfg->configured || !cfg->protect ) {
	return( DECLINED );
    }
    if (( cfg->host == NULL ) || ( cfg->redirect == NULL )
	    || ( cfg->service == NULL || cfg->posterror == NULL )) {
	fprintf( stderr, "Cosign is not configured correctly
		- check your setup\n" );
	return( FORBIDDEN );
    }

    /*
     * Look for cfg->service cookie. if there isn't one,
     * set it and redirect.
     */

    data = ap_table_get( r->headers_in, "Cookie" );

    while (data && *data && ( pair = ap_getword( r->pool, &data, ';'))) {
	if ( *data == ' ' ) ++data;
	cookiename = ap_getword( r->pool, &pair, '=');
	if ( strcasecmp( cookiename, cfg->service) == 0 ) {
	    /* we found a matching cookie */
	    goto validate_cookie;
	}
    }

    if ( set_cookie_and_redirect( r, cfg ) == 0 ) {
	return( HTTP_MOVED_TEMPORARILY );
    } else {
	return( FORBIDDEN );
    }

    /*
     * Validate cookie with backside server.  If we already have a cached
     * version of the data, just verify the cookie's still valid.
     * Otherwise, retrieve the auth info from the server.
     */

validate_cookie:
    my_cookie = ap_psprintf( r->pool, "%s=%s", cookiename, pair );
    strcpy( si.si_ipaddr, r->connection->remote_ip );
    if ( cookie_valid( cfg->sl, my_cookie, &si ) < 0 ) {
fprintf( stderr, "want to redirect now!\n" );
    #ifdef notdef
	if ( set_cookie_and_redirect( r, cfg ) == 0 ) {
	    return( HTTP_MOVED_TEMPORARILY );
	} else {
	    return( FORBIDDEN );
	}
    #endif notdef
    }
    ap_table_set( r->subprocess_env, "REMOTE_REALM", si.si_realm );
    r->connection->user = ap_pstrcat( r->pool, si.si_user, NULL);
    /* add in Kerberos info here */

    return( DECLINED );
}

    static const char *
set_cosign_protect( cmd_parms *params, void *mconfig, int flag )
{
    cosign_host_config		*cfg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	cfg = (cosign_host_config *)mconfig;
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
	cfg->sl = scfg->sl;
	cfg->port = scfg->port; 
    }

    if ( cfg->service != NULL ) {
	return( "Only one service per configuration allowed." );
    }

    cfg->service = ap_psprintf( params->pool,"cosign-%s", arg );
    cfg->configured = 1;
    return( NULL );
}

    static const char *
set_cosign_port( cmd_parms *params, void *mconfig, char *arg )
{
    cosign_host_config		*cfg;
    struct sinlist		*cur;
    unsigned short		portarg;

    if ( params->path == NULL ) {
	cfg = (cosign_host_config *) ap_get_module_config(
		params->server->module_config, &cosign_module );
    } else {
	return( "CosignPort not valid per dir!" );
    }

    portarg = strtol( arg, (char **)NULL, 10 );
    cfg->port = htons( portarg );

    for ( cur = cfg->sl; cur != NULL; cur = cur->s_next ) {
	cur->s_sin.sin_port = cfg->port;
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

    static const char *
set_cosign_host( cmd_parms *params, void *mconfig, char *arg )
{
    struct hostent		*he;
    int				i;
    struct sinlist		*new, **cur;
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
    cur = &cfg->sl;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	new = ( struct sinlist * )
		ap_palloc( params->pool, sizeof( struct sinlist ));
	memset( &new->s_sin, 0, sizeof( struct sockaddr_in ));
	new->s_sin.sin_family = AF_INET;
	new->s_sin.sin_port = cfg->port;
	memcpy( &new->s_sin.sin_addr.s_addr,
		he->h_addr_list[ i ], ( unsigned int)he->h_length );
	new->s_copied = 0;
fprintf( stderr, "setting ip address: %s ", inet_ntoa( *( struct in_addr *)he->h_addr_list[ i ] ));
	*cur = new;
	cur = &new->s_next;
    }
    *cur = NULL;
    return( NULL );
}

command_rec cosign_cmds[ ] =
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

        { NULL }
};

    void
cosign_child_cleanup( server_rec *s, pool *p )
{
    /* upon child exit, close all ropen SNETs */
    if ( teardown_conn() != 0 ) {
	fprintf( stderr, "teardown_conn: something bad happened\n" );
    }
    return;
}
module MODULE_VAR_EXPORT cosign_module = {
    STANDARD_MODULE_STUFF, 
    NULL,	           /* module initializer                  */
    cosign_create_dir_config, /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    cosign_create_server_config, /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    cosign_cmds,           /* table of config file commands       */
    NULL,		   /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    NULL,                  /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    cosign_auth,           /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,                  /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
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


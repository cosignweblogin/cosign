/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <utime.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>


#include <openssl/ssl.h>

#include <snet.h>

#ifdef LIGHTTPD
#include "base.h"
#include "logging.h"
#else /* !LIGHTTPD */
#include <httpd.h>
#include <http_log.h>
#endif /* LIGHTTPD */

#include "argcargv.h"
#include "sparse.h"
#include "mkcookie.h"
#include "log.h"
#include "cosign.h"
#include "cosignproto.h"

#define IDLETIME	60

    int
cosign_cookie_valid( cosign_host_config *cfg, char *cookie, char **rekey,
	struct sinfo *si, char *ipaddr, void *s )
{
    struct sinfo	lsi;
    ACAV		*acav;
    int			rc, fd, ac;
    int			i, j, newfile = 0;
    struct timeval	tv;
    char		path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    char		**av, *p;
    FILE		*tmpf;
    extern int		errno;

    if ( access( cfg->filterdb, R_OK | W_OK | X_OK ) != 0 ) {
	perror( cfg->filterdb );
	return( COSIGN_ERROR );
    }

    if ( mkcookiepath( cfg->filterdb, cfg->hashlen, cookie,
	    path, sizeof( path )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "cookie path too long" );
	return( COSIGN_ERROR );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ){
	perror( "cosign_cookie_valid" );
        return( COSIGN_ERROR );
    }

    memset( si, 0, sizeof( struct sinfo ));

retry:
    /*
     * read_scookie() return vals:
     * -1 system error
     * 0 ok
     * 1 not in filesystem
     */
    if (( newfile = read_scookie( path, &lsi, s )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: read_scookie error" );
	return( COSIGN_ERROR );
    }

    if ( !newfile && (( tv.tv_sec - lsi.si_itime ) <= IDLETIME )) {
	if (( cfg->checkip == IPCHECK_ALWAYS ) &&
		( strcmp( ipaddr, lsi.si_ipaddr ) != 0 )) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: cached ip %s does not match "
		    "browser ip %s", lsi.si_ipaddr, ipaddr );
	    goto netcheck;
	}

	/*
	 * to ensure that COSIGN_FACTORS is always populated,
	 * copy the factor list before checking to see if we
	 * meet required factors, since acav_parse is destructive.
	 * read_scookie zeros lsi, so if there's no factor line
	 * in the local cookie, this strcpy just sets si->si_factor
	 * to NULL.
	 */
	strcpy( si->si_factor, lsi.si_factor );
	
	/*
	 * check the factor list only if CosignRequireFactor is
	 * set. reqfc > 0 requires protocol 2.
	 */
	si->si_protocol = lsi.si_protocol;
	if ( cfg->reqfc > 0 &&
		COSIGN_PROTO_SUPPORTS_FACTORS( si->si_protocol )) {
	    if (( acav = acav_alloc()) == NULL ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: cookie_valid:"
			" acav_alloc failed" );
		return( COSIGN_ERROR );
	    }

	    if (( ac = acav_parse( acav, lsi.si_factor, &av )) < 0 ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: cookie_valid:"
			" acav_parse failed" );
		acav_free( acav );
		return( COSIGN_ERROR );
	    }

	    for ( i = 0; i < cfg->reqfc; i++ ) {
		for ( j = 0; j < ac; j++ ) {
		    if ( strcmp( cfg->reqfv[ i ], av[ j ] ) == 0 ) {
			break;
		    }
		}
		if ( j >= ac ) {
		    /* a required factor wasn't in the cached line */
		    break;
		}
	    }
	    acav_free( acav );
	    if ( i < cfg->reqfc ) {
		/* we broke out before all factors were satisfied */
		goto netcheck;
	    }
	}

	strcpy( si->si_ipaddr, lsi.si_ipaddr );
	strcpy( si->si_user, lsi.si_user );
	strcpy( si->si_realm, lsi.si_realm );

#ifdef KRB
	if ( cfg->krbtkt ) {
	    strcpy( si->si_krb5tkt, lsi.si_krb5tkt );
	}
#endif /* KRB */
	return( COSIGN_OK );
    }

netcheck:
    if (( rc = cosign_check_cookie( cookie, rekey, si, cfg, newfile, s ))
	    != COSIGN_OK ) {
	if ( rc == COSIGN_ERROR ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "Unable to connect to any Cosign server." ); 
	}
        return( rc );
    }

    if (( cfg->checkip == IPCHECK_ALWAYS ) &&
	    ( strcmp( ipaddr, si->si_ipaddr ) != 0 )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: server ip info %s does not match "
		"browser ip %s", si->si_ipaddr, ipaddr );
	return( COSIGN_RETRY );
    }

    if ( !newfile ) {
	/* since we're not getting the ticket everytime, we need
	 * to copy the info here so the ENV will be right.
	 */
#ifdef KRB
	if ( cfg->krbtkt ) {
	    strcpy( si->si_krb5tkt, lsi.si_krb5tkt );
	}
#endif /* KRB */

	/* check net info against local info */
	if ( strcmp( si->si_user, lsi.si_user ) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info %s does not match local info %s for "
		    "cookie %s", si->si_user, lsi.si_user, cookie );
	    return( COSIGN_ERROR );
	}
	if ( strcmp( si->si_realm, lsi.si_realm ) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info %s does not match local info %s for "
		    "cookie %s", si->si_realm, lsi.si_realm, cookie );
	    return( COSIGN_ERROR );
	}
	if ( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info %s does not match local info %s for "
		    "cookie %s", si->si_ipaddr, lsi.si_ipaddr, cookie );
	    goto storecookie;
	}

	if ( COSIGN_PROTO_SUPPORTS_FACTORS( si->si_protocol )) {
	    if ( strcmp( si->si_factor, lsi.si_factor ) != 0 ) {
		goto storecookie;
	    }
	}

	/* update to current time, pushing window forward */
	utime( path, NULL );
	return( COSIGN_OK );
    }

    if (( cfg->checkip == IPCHECK_INITIAL ) &&
	    ( strcmp( ipaddr, si->si_ipaddr ) != 0 )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: initial server ip info %s does not match "
		"browser ip %s", si->si_ipaddr, ipaddr );
	return( COSIGN_RETRY );
    }

    /* store local copy of scookie (service cookie) */
storecookie:
    if ( rekey != NULL ) {
	if ( *rekey == NULL ) {
	    cosign_log( APLOG_INFO, s, "mod_cosign: cosign_cookie_valid: "
			"rekey requested, but no rekeyed cookie returned, "
			"using original cookie value" );
	} else if ( mkcookiepath( cfg->filterdb, cfg->hashlen, *rekey,
		path, sizeof( path )) < 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
			"new cookie path too long" );
	    return( COSIGN_ERROR );
	}
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i", cfg->filterdb,
	    (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"tmppath too long" );
	return( COSIGN_ERROR );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"could not open %s", tmppath );
	perror( tmppath );
	return( COSIGN_ERROR );
    }

    if (( tmpf = fdopen( fd, "w" )) == NULL ) {
	if ( unlink( tmppath ) != 0 ) {
            cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"could not unlink %s", tmppath ); 
	    perror( tmppath );
	}
        cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
	    "could not fdopen %s", tmppath ); 
	perror( tmppath );
	return( COSIGN_ERROR );
    }

    fprintf( tmpf, "v%d\n", si->si_protocol );
    fprintf( tmpf, "i%s\n", si->si_ipaddr );
    fprintf( tmpf, "p%s\n", si->si_user );
    fprintf( tmpf, "r%s\n", si->si_realm );
    if ( COSIGN_PROTO_SUPPORTS_FACTORS( si->si_protocol )) {
	fprintf( tmpf, "f%s\n", si->si_factor );
    }

#ifdef KRB
    if ( si->si_krb5tkt && *si->si_krb5tkt ) {
	fprintf( tmpf, "k%s\n", si->si_krb5tkt );
    }
#endif /* KRB */

    if ( fclose ( tmpf ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
            cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
	        "could not unlink(2) %s", tmppath ); 
	    perror( tmppath );
	}
        cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
	    "could not fclose %s", tmppath ); 
	perror( tmppath );
	return( COSIGN_ERROR );
    }

    if ( !newfile ) {
        if ( rename( tmppath, path ) != 0 ) {
            cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
	        "could not rename %s", tmppath ); 
	    perror( tmppath );
	    return( COSIGN_ERROR );
        }
    } else {
	if ( link( tmppath, path ) != 0 ) {
	    if ( unlink( tmppath ) != 0 ) {
                cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
	            "could not unlink(3) %s", tmppath ); 
		perror( tmppath );
	    }
	    goto retry;
	}

	if ( unlink( tmppath ) != 0 ) {
            cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
	        "could not unlink(4) %s", tmppath ); 
	    perror( tmppath );
	}
    }

    return( COSIGN_OK );
}

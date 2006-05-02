/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

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

#include <httpd.h>
#include <http_log.h>

#include <openssl/ssl.h>

#include <snet.h>
#include "argcargv.h"
#include "sparse.h"
#include "mkcookie.h"
#include "log.h"
#include "cosign.h"

#define IDLETIME	60

extern int		cosign_protocol;

    int
cosign_cookie_valid( cosign_host_config *cfg, char *cookie, struct sinfo *si,
	char *ipaddr, server_rec *s )
{
    struct sinfo	lsi;
    ACAV		*acav;
    int			rc, rs, fd, ac;
    int			i, j, addfactors = 0;
    struct timeval	tv;
    char		path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    char		**av;
    FILE		*tmpfile;
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

    /*
     * rs return vals:
     * -1 system error
     * 0 ok
     * 1 not in filesystem
     */
    if (( rs = read_scookie( path, &lsi, s )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: read_scookie error" );
	return( COSIGN_ERROR );
    }

    if (( rs == 0 ) && (( tv.tv_sec - lsi.si_itime ) <= IDLETIME )) {
	if (( cfg->checkip == IPCHECK_ALWAYS ) &&
		( strcmp( ipaddr, lsi.si_ipaddr ) != 0 )) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: cached ip %s does not match "
		    "browser ip %s", lsi.si_ipaddr, ipaddr );
	    return( COSIGN_ERROR );
	}
	strcpy( si->si_ipaddr, lsi.si_ipaddr );
	strcpy( si->si_user, lsi.si_user );
	strcpy( si->si_realm, lsi.si_realm );

	if (( cosign_protocol == 2 ) && ( cfg->reqfc > 0 )) {
	    if (( acav = acav_alloc()) == NULL ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: cookie_valid:"
			" acav_alloc failed" );
		return( COSIGN_ERROR );
	    }

	    if (( ac = acav_parse( acav, lsi.si_factor, &av )) < 0 ) {
		cosign_log( APLOG_ERR, s, "mod_cosign: cookie_valid:"
			" acav_parse failed" );
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
	    if ( i < cfg->reqfc ) {
		/* we broke out before all factors were satisfied */
		goto netcheck;
	    }
	    strcpy( si->si_factor, lsi.si_factor );
	}

#ifdef KRB
	if ( cfg->krbtkt ) {
	    strcpy( si->si_krb5tkt, lsi.si_krb5tkt );
	}
#endif /* KRB */
	return( COSIGN_OK );
    }

netcheck:
    if (( rc = cosign_check_cookie( cookie, si, cfg, rs, s ))
	    == COSIGN_ERROR ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"Unable to connect to any Cosign server." ); 
        return( COSIGN_ERROR );
    }

    if ( rc == COSIGN_RETRY ) {
	return( COSIGN_RETRY );
    }

    if (( cfg->checkip == IPCHECK_ALWAYS ) &&
	    ( strcmp( ipaddr, si->si_ipaddr ) != 0 )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: server ip info %s does not match "
		"browser ip %s", si->si_ipaddr, ipaddr );
	return( COSIGN_ERROR );
    }

    if ( rs == 0 ) {
	/* check net info against local info */
	if ( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info %s does not match local info %s for "
		    "cookie %s", si->si_ipaddr, lsi.si_ipaddr, cookie );
	    return( COSIGN_ERROR );
	}
	if ( strcmp( si->si_user, lsi.si_user ) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info %s does not match local info %s for "
		    "cookie %s", si->si_user, lsi.si_user, cookie );
	}
	if ( strcmp( si->si_realm, lsi.si_realm ) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info %s does not match local info %s for "
		    "cookie %s", si->si_realm, lsi.si_realm, cookie );
	    return( COSIGN_ERROR );
	}

	if ( cosign_protocol == 2 ) {
	    if ( strcmp( si->si_factor, lsi.si_factor ) != 0 ) {
		addfactors = 1;
		goto storecookie;
	    }
	}

	/* since we're not getting the ticket everytime, we need
	 * to copy the info here so the ENV will be right.
	 */

#ifdef KRB
	if ( cfg->krbtkt ) {
	    strcpy( si->si_krb5tkt, lsi.si_krb5tkt );
	}
#endif /* KRB */
	/* update to current time, pushing window forward */
	utime( path, NULL );
	return( COSIGN_OK );
    }

storecookie:
    /* store local copy of scookie (service cookie) */
    if (( cfg->checkip == IPCHECK_INITIAL ) &&
	    ( strcmp( ipaddr, si->si_ipaddr ) != 0 )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: initial server ip info %s does not match "
		"browser ip %s", si->si_ipaddr, ipaddr );
	return( COSIGN_ERROR );
    }
    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i", cfg->filterdb,
	    (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"tmppath too long" );
	return( COSIGN_ERROR );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	perror( tmppath );
	return( COSIGN_ERROR );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}
	perror( tmppath );
	return( COSIGN_ERROR );
    }

    fprintf( tmpfile, "i%s\n", si->si_ipaddr );
    fprintf( tmpfile, "p%s\n", si->si_user );
    fprintf( tmpfile, "r%s\n", si->si_realm );
    if ( cosign_protocol == 2 ) {
	fprintf( tmpfile, "f%s\n", si->si_factor );
    }

#ifdef KRB
    if ( rs ) {
	fprintf( tmpfile, "k%s\n", si->si_krb5tkt );
    }
#endif /* KRB */

    if ( fclose ( tmpfile ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}
	perror( tmppath );
	return( COSIGN_ERROR );
    }

    if ( addfactors ) {
        if ( rename( tmppath, path ) != 0 ) {
	    perror( tmppath );
	    return( COSIGN_ERROR );
        }
    } else {
	if ( link( tmppath, path ) != 0 ) {
	    if ( unlink( tmppath ) != 0 ) {
		perror( tmppath );
	    }
	    perror( tmppath );
	    return( COSIGN_ERROR );
	}

	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}
    }

    return( COSIGN_OK );
}

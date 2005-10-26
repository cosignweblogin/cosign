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
#include "sparse.h"
#include "cosign.h"
#include "log.h"

#define IDLETIME	60

    int
cosign_cookie_valid( cosign_host_config *cfg, char *cookie, struct sinfo *si,
	char *ipaddr, server_rec *s )
{
    struct sinfo	lsi;
    int			rc, rs, fd;
    struct timeval	tv;
    char		path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    FILE		*tmpfile;
    extern int		errno;

    if ( access( cfg->filterdb, R_OK | W_OK | X_OK ) != 0 ) {
	perror( cfg->filterdb );
	return( COSIGN_ERROR );
    }

    if ( strchr( cookie, '/' ) != NULL ) {
	cosign_log( APLOG_ERR, s,
	            "mod_cosign: cosign_cookie_valid: cookie contains '/'" );
	return( COSIGN_ERROR );
    }

    if ( snprintf( path, sizeof( path ), "%s/%s", cfg->filterdb, cookie ) >=
	    sizeof( path )) {
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
#ifdef CHECK_SOURCE_ADDR
	if ( strcmp( ipaddr, lsi.si_ipaddr ) != 0 ) {
	    return( COSIGN_ERROR );
	}
#endif /* CHECK_SOURCE_ADDR */
	strcpy( si->si_ipaddr, lsi.si_ipaddr );
	strcpy( si->si_user, lsi.si_user );
	strcpy( si->si_realm, lsi.si_realm );

#ifdef KRB
	if ( cfg->krbtkt ) {
#ifdef KRB4
	    strcpy( si->si_krb4tkt, lsi.si_krb4tkt );
#endif /* krb4 */
	    strcpy( si->si_krb5tkt, lsi.si_krb5tkt );
	}
#endif /* KRB */
	return( COSIGN_OK );
    }

    if (( rc = cosign_check_cookie( cookie, si, cfg, rs, s ))
	    == COSIGN_ERROR ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"Unable to connect to any Cosign server." ); 
        return( COSIGN_ERROR );
    }

    if ( rc == COSIGN_RETRY ) {
	return( COSIGN_RETRY );
    }

#ifdef CHECK_SOURCE_ADDR
    if ( strcmp( ipaddr, si->si_ipaddr ) != 0 ) {
	return( COSIGN_ERROR );
    }
#endif /* CHECK_SOURCE_ADDR */

    if ( rs == 0 ) {
	/* check net info against local info */
	if (( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) ||
		( strcmp( si->si_user, lsi.si_user ) != 0 ) ||
		( strcmp( si->si_realm, lsi.si_realm ) != 0 )) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info does not match local info for %s", cookie );
	    return( COSIGN_ERROR );
	}

	/* since we're not getting the ticket everytime, we need
	 * to copy the info here so the ENV will be right.
	 */

#ifdef KRB
	if ( cfg->krbtkt ) {
#ifdef KRB4
	    strcpy( si->si_krb4tkt, lsi.si_krb4tkt );
#endif /* krb4 */
	    strcpy( si->si_krb5tkt, lsi.si_krb5tkt );
	}
#endif /* KRB */
	/* update to current time, pushing window forward */
	utime( path, NULL );
	return( COSIGN_OK );
    }

    /* store local copy of scookie (service cookie) */
    /* XXX get path to store here */
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

#ifdef KRB
    if ( rs ) {
	fprintf( tmpfile, "k%s\n", si->si_krb5tkt );
#ifdef KRB4
	fprintf( tmpfile, "K%s\n", si->si_krb4tkt );
#endif /* KRB4 */
    }
#endif /* KRB */

    if ( fclose ( tmpfile ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}
	perror( tmppath );
	return( COSIGN_ERROR );
    }

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

    return( COSIGN_OK );
}

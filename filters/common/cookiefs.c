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
	return( -1 );
    }

    if ( strchr( cookie, '/' ) != NULL ) {
	cosign_log( APLOG_ERR, s,
	            "mod_cosign: cosign_cookie_valid: cookie contains '/'" );
	return( -1 );
    }

    if ( snprintf( path, sizeof( path ), "%s/%s", cfg->filterdb, cookie ) >=
	    sizeof( path )) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "cookie path too long" );
	return( -1 );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ){
	perror( "cosign_cookie_valid" );
        return( -1 );
    }

    /*
     * -1 bummer
     * 0 ok
     * 1 not in fs
     */
    if (( rs = read_scookie( path, &lsi, s )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: read_scookie error" );
	return( -1 );
    }

    if (( rs == 0 ) && (( tv.tv_sec - lsi.si_itime ) <= IDLETIME )) {
#ifdef CHECK_SOURCE_ADDR
	if ( strcmp( ipaddr, lsi.si_ipaddr ) != 0 ) {
	    return( -1 );
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
	return( 0 );
    }

    if (( rc = cosign_check_cookie( cookie, si, cfg, rs, s )) < 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"check_cookie error" );
        return( -1 );
    }

    if ( rc == 2 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"Unable to connect to any Cosign server." ); 
	return( -1 );
    }

    if ( rc == 1 ) {
	return( 1 );
    }

#ifdef CHECK_SOURCE_ADDR
    if ( strcmp( ipaddr, si->si_ipaddr ) != 0 ) {
	return( 1 );
    }
#endif /* CHECK_SOURCE_ADDR */

    if ( rs == 0 ) {
	/* check net info against local info */
	if (( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) ||
		( strcmp( si->si_user, lsi.si_user ) != 0 ) ||
		( strcmp( si->si_realm, lsi.si_realm ) != 0 )) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		    "network info does not match local info for %s", cookie );
	    return( -1 );
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
	return( 0 );
    }

    /* store local copy of scookie (service cookie) */
    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i", cfg->filterdb,
	    tv.tv_sec, tv.tv_usec, (int)getpid()) >= sizeof( tmppath )) {
	cosign_log( APLOG_ERR, s, "mod_cosign: cosign_cookie_valid: "
		"tmppath too long" );
	return( -1 );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
	perror( tmppath );
	return( -1 );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}
	perror( tmppath );
	return( -1 );
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
	return( -1 );
    }

    if ( link( tmppath, path ) != 0 ) {
	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}
	perror( tmppath );
	return( -1 );
    }

    if ( unlink( tmppath ) != 0 ) {
	perror( tmppath );
    }

    return( 0 );
}

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

#include <openssl/ssl.h>

#include <snet.h>
#include "sparse.h"
#include "cosign.h"

#define IDLETIME	60

static char	*filterdb = _FILTER_DB;

    int
cosign_cookie_valid( cosign_host_config *cfg, char *cookie, struct sinfo *si,
	char *ipaddr )
{
    struct sinfo	lsi;
    int			rc, rs, fd, tkt = 0;
    struct timeval	tv;
    char		path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    FILE		*tmpfile;
    extern int		errno;

    if ( access( filterdb, R_OK | W_OK | X_OK ) != 0 ) {
	perror( filterdb );
	return( -1 );
    }

    if ( strchr( cookie, '/' ) != NULL ) {
	fprintf( stderr, "cosign_cookie_valid: cookie contains '/'\n" );
	return( -1 );
    }

    if ( snprintf( path, MAXPATHLEN, "%s/%s", filterdb, cookie ) >= MAXPATHLEN ) {
	fprintf( stderr, "cosign_cookie_valid: cookie too long\n" );
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
    if (( rs = read_scookie( path, &lsi )) < 0 ) {
	fprintf( stderr, "Something's wrong: read_scookie\n" ); 
	return( -1 );
    }

    if (( rs == 0 ) && (( tv.tv_sec - lsi.si_itime ) <= IDLETIME )) {
	if ( strcmp( ipaddr, lsi.si_ipaddr ) != 0 ) {
	    return( -1 );
	}
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

#ifdef KRB
    if (( rs == 1 ) && ( cfg->krbtkt )) {
        tkt = 1;
    }
#endif /* KRB */

    if (( rc = cosign_check_cookie( cookie, si, cfg, tkt )) < 0 ) {
        fprintf( stderr, "cosign_cookie_valid: check_cookie failed\n" );
        return( -1 );
    }


    if ( rc == 2 ) {
	fprintf( stderr, "Unable to connect to any Cosign server." ); 
	return( -1 );
    }

    if ( rc == 1 ) {
	return( 1 );
    }

    if ( strcmp( ipaddr, si->si_ipaddr ) != 0 ) {
	return( 1 );
    }

    if ( rs == 0 ) {
	/* check net info against local info */
	if (( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) ||
		( strcmp( si->si_user, lsi.si_user ) != 0 ) ||
		( strcmp( si->si_realm, lsi.si_realm ) != 0 )) {
	    fprintf( stderr, "network info does not match local info for %s\n",
		    cookie );
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
    if ( snprintf( tmppath, MAXPATHLEN, "%s/%x%x.%i", filterdb,
	    tv.tv_sec, tv.tv_usec, (int)getpid()) >= MAXPATHLEN ) {
	fprintf( stderr, "cookiefs: tmppath too long\n" );
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
    if ( tkt ) {
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

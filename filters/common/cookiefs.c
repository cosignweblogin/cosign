/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <snet.h>
#include <fcntl.h>
#include <errno.h>

#include "sparse.h"
#include "cosign.h"

#define CPATH		"/var/cosigndb"
#define IDLETIME	60

    int
cookie_valid( struct sinlist *s_cur, char *cookie, struct sinfo *si )
{
    struct sinfo	lsi, nsi;
    int			rs, fd;
    struct timeval	tv;
    char		path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    FILE		*tmpfile;
    extern int		errno;

    if ( strchr( cookie, '/' ) != NULL ) {
	fprintf( stderr, "cookie_valid: cookie contains '/'\n" );
	return( -1 );
    }

    if ( snprintf( path, MAXPATHLEN, "%s/%s", CPATH, cookie ) >= MAXPATHLEN ) {
	fprintf( stderr, "cookie_valid: cookie too long\n" );
	return( -1 );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ){
	perror( "cookie_valid" );
        return( -1 );
    }

    switch ( rs = read_a_secant( path, &lsi )) {

    case SECANT_OK:
	/* if we're in the window */
	if (( tv.tv_sec - lsi.si_itime ) <= IDLETIME ) {
fprintf( stderr, "We're in the window\n" );
	    if ( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) {
		return( -1 );
	    }
	    strcpy( si->si_user, lsi.si_user );
	    strcpy( si->si_realm, lsi.si_realm );
	    return( 0 );
	}
fprintf( stderr, "Not in the window\n" );
	break;

    case SECANT_NOT_IN_FS:
fprintf( stderr, "Not in the fs\n" );
	/* I'm sure we can do something more clever here XXX */
	break;

    default:
	fprintf( stderr, "Something's wrong: read_a_secant\n" ); 
	return( -1 );
    }

    copy_connections( s_cur ); 

    if ( netcheck_cookie( cookie, &nsi ) < 0 ) {
	fprintf( stderr, "cookie_valid: netcheck_cookie failed\n" );
	return( -1 );
    }

    if ( rs == SECANT_NOT_IN_FS ) {

	/* store local copy of secant */
	if ( snprintf( tmppath, MAXPATHLEN, "%s/%x%x.%i", CPATH,
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

	fprintf( tmpfile, "i%s\n", nsi.si_ipaddr );
	fprintf( tmpfile, "p%s\n", nsi.si_user );
	fprintf( tmpfile, "r%s\n", nsi.si_realm );

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
	    if( errno == EEXIST ) {
		perror( path );
		return( -1 );
	    }
	    perror( tmppath );
	    return( -1 );
	}

	if ( unlink( tmppath ) != 0 ) {
	    perror( tmppath );
	}

    } else {
	/* check net info against local info */
	if (( strcmp( nsi.si_ipaddr, lsi.si_ipaddr ) != 0 ) ||
		( strcmp( nsi.si_user, lsi.si_user ) != 0 ) ||
		( strcmp( nsi.si_realm, lsi.si_realm ) != 0 )) {
	    fprintf( stderr, "network info does not match local info for %s\n",
		    cookie );
	    return( -1 );
	}
    }

    /* copy the info for the module to propogate */
    strcpy( si->si_ipaddr, nsi.si_ipaddr );
    strcpy( si->si_user, nsi.si_user );
    strcpy( si->si_realm, nsi.si_realm );

    /* update to current time, pushing window forward */
    utime( path, NULL );

    return( 0 );
}

/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include "cparse.h"

#define MAXLEN 256

    int
read_a_cookie( char *path, struct cinfo *ci )
{
    FILE	*cf;
    struct stat	st;
    char	buf[ MAXLEN ];
    char	*p;
    int		len;

    if (( cf = fopen( path, "r" )) == NULL ) {
	syslog( LOG_ERR, "read_a_cookie: %s: %m", path  );
	return( -1 );
    }

    if ( fstat( fileno( cf ), &st ) != 0 ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: %s: %m", path );
	return( -1 );
    }

    ci->ci_itime = st.st_mtime;

    /* file ordering matters for version and state, after we don't care */
    if ( fgets( buf, sizeof( ci->ci_version ), cf ) == NULL ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: ci_version: %m"  );
	return( -1 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: line too long" );
	return( -1 );
    }
    buf[ len -1 ] = '\0';

    if ( *buf != 'v' ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: file format error" );
	return( -1 );
    }
    p = buf + 1;

    ci->ci_version = atoi( p );

    if ( ci->ci_version != 0 ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: file version mismatch" );
	return( -1 );
    }

    if ( fgets( buf, sizeof( ci->ci_state ), cf ) == NULL ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: ci_state %m"  );
	return( -1 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_a_cookie: line too long" );
    }
    buf[ len -1 ] = '\0';

    if ( *buf != 's' ) {
	syslog( LOG_ERR, "read_a_cookie: file format error" );
	(void)fclose( cf );
	return( -1 );
    }
    p = buf + 1;

    ci->ci_state = atoi( p );

    while( fgets( buf, MAXLEN, cf ) != NULL ) {
	len = strlen( buf );
	if ( buf[ len - 1 ] != '\n' ) {
	    (void)fclose( cf );
	    syslog( LOG_ERR, "read_a_cookie: line too long");
	}
	buf[ len -1 ] = '\0';
	p = buf + 1;

	switch( *buf ) {

	case 'i':
	    strcpy( ci->ci_ipaddr, p );
	    break;

	case 'p':
	    strcpy( ci->ci_user, p );
	    break;

	case 'r':
	    strcpy( ci->ci_realm, p );
	    break;

	case 't':
	    strcpy( ci->ci_ctime, p );
	    break;

	default:
	    syslog( LOG_ERR, "read_a_cooke: unknown keyword %c", *buf );
	    (void)fclose( cf );
	    return( -1 );
	}
    }

    if ( fclose( cf ) != 0 ) {
	syslog( LOG_ERR, "read_a_cookie: %s: %m", path );
	return( -1 );
    }
    return( 0 );
}


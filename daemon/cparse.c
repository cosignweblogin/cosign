/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "cparse.h"

#define MAXLEN 256

    int
do_logout( char *path )
{
    int		fd;

    if (( fd = open( path, O_WRONLY, 0644 )) < 0 ) {
        syslog( LOG_ERR, "do_logout: %s: %m", path );
        return( -1 );
    }

    if ( lseek( fd, 4, SEEK_SET ) == -1 ) {
        (void)close( fd );
        syslog( LOG_ERR, "do_logout: %s: %m", path );
        return( -1 );
    }

    if ( write( fd, "0", 1 ) == -1 ) {
        (void)close( fd );
        syslog( LOG_ERR, "do_logout: %s: %m", path );
        return( -1 );
    }

    if ( close( fd ) != 0 ) {
        syslog( LOG_ERR, "do_logout: %s: %m", path );
        return( -1 );
    }

    return( 0 );
}

    int
service_to_login( char *service, char *login )
{
    FILE	*scf;
    char	buf[ MAXPATHLEN ];
    char	*p;
    int		len;

    if (( scf = fopen( service, "r" )) == NULL ) {
	syslog( LOG_ERR, "service_to_login: %s: %m", service  );
	return( -1 );
    }

    if ( fgets( buf, sizeof( buf ), scf ) == NULL ) {
	(void)fclose( scf );
	syslog( LOG_ERR, "service_to_login: fgets: %m"  );
	return( -1 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	(void)fclose( scf );
	syslog( LOG_ERR, "service_to_login: line too long" );
	return( -1 );
    }
    buf[ len -1 ] = '\0';

    if ( *buf != 'l' ) {
	(void)fclose( scf );
	syslog( LOG_ERR,
		"service_to_login: file format error in %s", service );
	return( -1 );
    }
    p = buf + 1;

    strcpy( login, p );

    if ( fclose( scf ) != 0 ) {
	syslog( LOG_ERR, "service_to_login: %s: %m", service );
	return( -1 );
    }
    return( 0 );
}

    int
read_cookie( char *path, struct cinfo *ci )
{
    FILE	*cf;
    struct stat	st;
    char	buf[ MAXLEN ];
    char	*p;
    int		len;

    if (( cf = fopen( path, "r" )) == NULL ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path  );
	return( -1 );
    }

    if ( fstat( fileno( cf ), &st ) != 0 ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
	return( -1 );
    }

    ci->ci_itime = st.st_atime;

    /* file ordering matters for version and state, after we don't care */
    if ( fgets( buf, sizeof( ci->ci_version ), cf ) == NULL ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: ci_version: %m"  );
	return( -1 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: line too long" );
	return( -1 );
    }
    buf[ len -1 ] = '\0';

    if ( *buf != 'v' ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: file format error" );
	return( -1 );
    }
    p = buf + 1;

    ci->ci_version = atoi( p );

    if ( ci->ci_version != 0 ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: file version mismatch" );
	return( -1 );
    }

    if ( fgets( buf, sizeof( ci->ci_state ), cf ) == NULL ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: ci_state %m"  );
	return( -1 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	(void)fclose( cf );
	syslog( LOG_ERR, "read_cookie: line too long" );
    }
    buf[ len -1 ] = '\0';

    if ( *buf != 's' ) {
	syslog( LOG_ERR, "read_cookie: file format error" );
	(void)fclose( cf );
	return( -1 );
    }
    p = buf + 1;

    ci->ci_state = atoi( p );

    while( fgets( buf, MAXLEN, cf ) != NULL ) {
	len = strlen( buf );
	if ( buf[ len - 1 ] != '\n' ) {
	    (void)fclose( cf );
	    syslog( LOG_ERR, "read_cookie: line too long");
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

	case 'k':
	    strcpy( ci->ci_krbtkt, p );
	    break;

	default:
	    syslog( LOG_ERR, "read_cooke: unknown keyword %c", *buf );
	    (void)fclose( cf );
	    return( -1 );
	}
    }

    if ( fclose( cf ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
	return( -1 );
    }
    return( 0 );
}


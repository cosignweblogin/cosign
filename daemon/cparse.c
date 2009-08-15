/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>

#include "cparse.h"
#include "mkcookie.h"

    int
do_logout( char *path )
{
    if ( chmod( path, (  S_ISGID | S_IRUSR  )) < 0 ) {
	syslog( LOG_ERR, "do_logout: %s: %m", path  );
	return( -1 ) ;
    }
    utime( path, NULL );

    return( 0 );
}

/* char *login passed in should be MAXCOOKIELEN */
    int
service_to_login( char *service, char *login )
{
    FILE	*scf;
    char	buf[ MAXCOOKIELEN + 2 ];
    char	*p;
    int		len;
    extern int	errno;

    if (( scf = fopen( service, "r" )) == NULL ) {
	if ( errno != ENOENT ) {
	    syslog( LOG_ERR, "service_to_login: %s: %m", service  );
	}
	return( -1 );
    }

    if ( fgets( buf, sizeof( buf ), scf ) == NULL ) {
	syslog( LOG_ERR, "service_to_login: fgets: %m"  );
	goto error;
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	syslog( LOG_ERR, "service_to_login: line too long" );
	goto error;
    }
    buf[ len - 1 ] = '\0';
    p = buf + 1;

    if ( *buf != 'l' ) {
	syslog( LOG_ERR,
		"service_to_login: file format error in %s", service );
	goto error;
    }

    strcpy( login, p );

    if ( fclose( scf ) != 0 ) {
	syslog( LOG_ERR, "service_to_login: %s: %m", service );
	return( -1 );
    }
    return( 0 );

error:
    if ( fclose( scf ) != 0 ) {
	syslog( LOG_ERR, "service_to_login: %s: %m", service );
    }
    return( -1 );

}

    int
read_cookie( char *path, struct cinfo *ci )
{
    FILE		*cf;
    struct stat		st;
    char		buf[ MAXPATHLEN + 2 ];
    char		*p;
    int			len;
    extern int          errno;

    memset( ci, 0, sizeof( struct cinfo ));

    if (( cf = fopen( path, "r" )) == NULL ) {
	/* monster need this ENOENT return val */
	if ( errno == ENOENT ) {
	    return( 1 );
	}
	syslog( LOG_ERR, "read_cookie: %s: %m", path  );
	return( -1 );
    }

    if ( fstat( fileno( cf ), &st ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
	goto error;
    }

    ci->ci_itime = st.st_mtime;

    /* file ordering only matters for version and state */
    if ( fgets( buf, sizeof( ci->ci_version ), cf ) == NULL ) {
	syslog( LOG_ERR, "read_cookie: ci_version: %m"  );
	goto error;
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	syslog( LOG_ERR, "read_cookie: line too long" );
	goto error;
    }
    buf[ len - 1 ] = '\0';

    if ( *buf != 'v' ) {
	syslog( LOG_ERR, "read_cookie: file format error" );
	goto error;
    }
    p = buf + 1;

    ci->ci_version = atoi( p );

    if ( ci->ci_version != 2 ) {
	syslog( LOG_ERR, "read_cookie: file version mismatch" );
	goto error;
    }

    /* legacy logout code, skip the s0/1 line */
    if ( fgets( buf, sizeof( ci->ci_state ), cf ) == NULL ) {
	syslog( LOG_ERR, "read_cookie: ci_state: %m"  );
	goto error;
    }

    /* new logout code */
    if ( st.st_mode & S_ISGID ) {
	ci->ci_state = 0;
    } else {
	ci->ci_state = 1;
    }

    /* we checked sizes when we wrote this data to a trusted file system */
    while( fgets( buf, sizeof( buf ), cf ) != NULL ) {
	len = strlen( buf );
	if ( buf[ len - 1 ] != '\n' ) {
	    syslog( LOG_ERR, "read_cookie: line too long");
	    goto error;
	}
	buf[ len - 1 ] = '\0';
	p = buf + 1;

	switch( *buf ) {

	case 'i':
	    strcpy( ci->ci_ipaddr, p );
	    break;

	case 'j':
	    strcpy( ci->ci_ipaddr_cur, p );
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
	    syslog( LOG_ERR, "read_cookie: unknown keyword %c", *buf );
	    goto error;
	}
    }

    if ( fclose( cf ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
	return( -1 );
    }
    return( 0 );

error:
    if ( fclose( cf ) != 0 ) {
	syslog( LOG_ERR, "read_cookie: %s: %m", path );
    }
    return( -1 );
}


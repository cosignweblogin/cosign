/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sparse.h"

#define MAXLEN 256

    int
read_secant( char *path, struct sinfo *si )
{
    FILE	*sf;
    struct stat	st;
    char	buf[ MAXLEN ];
    char	*p;
    int		len;

    if (( sf = fopen( path, "r" )) == NULL ) {
	perror( path );
	return( 1 );
    }

    if ( fstat( fileno( sf ), &st ) != 0 ) {
	(void)fclose( sf );
	perror( path );
	return( -1 );
    }

    si->si_itime = st.st_mtime;

    while( fgets( buf, MAXLEN, sf ) != NULL ) {
	len = strlen( buf );
	if ( buf[ len - 1 ] != '\n' ) {
	    (void)fclose( sf );
	    fprintf( stderr, "read_secant: line too long");
	    return( -1 );
	}
	buf[ len -1 ] = '\0';
	p = buf + 1;

	switch( *buf ) {

	case 'i':
	    strcpy( si->si_ipaddr, p );
	    break;

	case 'p':
	    strcpy( si->si_user, p );
	    break;

	case 'r':
	    strcpy( si->si_realm, p );
	    break;
#ifdef KRB
	case 'k':
	    strcpy( si->si_krb5tkt, p );
	    break;
#ifdef KRB4
	case 'K':
	    strcpy( si->si_krb4tkt, p );
	    break;
#endif /* KRB4 */
#endif /* KRB */

	default:
	    fprintf( stderr, "read_secant: unknown keyword %c", *buf );
	    (void)fclose( sf );
	    return( -1 );
	}
    }

    if ( fclose( sf ) != 0 ) {
	fprintf( stderr, "read_secant: %s:\n", path );
	return( -1 );
    }
    return( 0 );
}


/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <snet.h>

#include "sparse.h"
#include "cosign.h"

#define CPATH	"/var/cosigndb"

    int
cookie_valid( struct sinlist *s_cur, char *cookie, struct sinfo *si )
{
    struct sinfo	lsi, nsi;
    char		path[ MAXPATHLEN ];

    if ( snprintf( path, MAXPATHLEN, "%s/%s", CPATH, cookie ) >= MAXPATHLEN ) {
	fprintf( stderr, "cookie_valid: cookie too long\n" );
	return( -1 );
    }

    switch ( read_a_secant( path, &lsi )) {

    case SECANT_OK:
	/* if we're in the window */
	if ( strcmp( si->si_ipaddr, lsi.si_ipaddr ) != 0 ) {
	    return( -1 );
	}
	strcpy( si->si_user, lsi.si_user );
	strcpy( si->si_realm, lsi.si_realm );
	return( 0 );

    case SECANT_NOT_IN_FS:
	//goto validate;
	return( -1 );

    default:
	break;
    }


    if (( copy_connections( s_cur )) != 0 ) {
	return( 1 );
    }


#ifdef notdef
check cookie in fs
    yes check cache expired
        yes revalidate
            yes setup env
        else
            no there an error
    no go to setup env
else
    check_net_cookie( cookie, &nsi )
     setup env
#endif notdef

   return( 0 );
}

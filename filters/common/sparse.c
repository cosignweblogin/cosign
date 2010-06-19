/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <snet.h>

#ifdef LIGHTTPD
#include "base.h"
#include "logging.h"
#else /* !LIGHTTPD */
#include <httpd.h>
#include <http_log.h>
#endif /* LIGHTTPD */

#include "sparse.h"
#include "log.h"

#define MAXLEN 256

    int
read_scookie( char *path, struct sinfo *si, void *s )
{
    SNET	*sn;
    struct stat	st;
    char	*p, *line;

    memset( si, 0, sizeof( struct sinfo ));

    if (( sn = snet_open( path, O_RDONLY, 0, 0 )) == NULL ) {
	if ( errno != ENOENT ) {
	    perror( path );
	}
	return( 1 );
    }

    if ( fstat( snet_fd( sn ), &st ) != 0 ) {
	(void)snet_close( sn );
	perror( path );
	return( -1 );
    }

    si->si_itime = st.st_mtime;

    while (( line = snet_getline( sn, NULL )) != NULL ) {
	p = line + 1;

	switch( line[0] ) {

	case 'v':
	    errno = 0;
            si->si_protocol = strtol( p, (char **)NULL, 10 );
            if ( errno ) {
                cosign_log( APLOG_NOTICE, s, "mod_cosign: read_scookie: "
                            "invalid protocol version %s, "
                            "falling back to protocol v0.", p );
                si->si_protocol = 0;
            }
	    break;

	case 'i':
	    strcpy( si->si_ipaddr, p );
	    break;

	case 'p':
	    strcpy( si->si_user, p );
	    break;

	case 'r':
	    strcpy( si->si_realm, p );
	    break;

	case 'f':
	    strcpy( si->si_factor, p );
	    break;
#ifdef KRB
	case 'k':
	    strcpy( si->si_krb5tkt, p );
	    break;
#endif /* KRB */

	default:
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: read_scookie: unknown key %c", line[0] );
	    (void)snet_close( sn );
	    return( -1 );
	}
    }

    if ( snet_close( sn ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: read_scookie: %s", path );
	return( -1 );
    }
    return( 0 );
}

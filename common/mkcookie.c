#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>

#include "fbase64.h"
#include "mkcookie.h"


static char	valid_tab[ 256 ] = {
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 1, 0, 1, 1, 0,
 1, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 0, 0, 0, 1, 0, 0,
 0, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 1, 0, 0, 0, 0, 1,
 0, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 1, 1, 1, 1, 1, 1,
 1, 1, 1, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
 0, 0, 0, 0, 0, 0, 0, 0,
};

    int
validcookie( char *cookie )
{
    char	*p;

    for ( p = cookie; *p != '\0'; p++ ) {
	if ( !valid_tab[ (unsigned char)*p ] ) {
	    return( 0 );
	}
    }
    return( 1 );
}

    int
mkcookie( int len, char *buf )
{
    unsigned char	tmp[ 1024 ];
    int			randbytes;			

    len -= 3; /* XXX why? */
    randbytes = SZ_FBASE64_D( len );
    if (( randbytes <= 0 ) || ( randbytes > sizeof( tmp ))) {
	return( -1 );
    }

    if ( RAND_bytes( tmp, randbytes ) != 1 ) {
        return( -2 );
    }

    fbase64_e( tmp, randbytes, buf );
    return( 0 );
}


    int
mkcookiepath( char *prefix, int hashlen, char *cookie, char *buf, int len )
{
    char	*p;
    int		prefixlen, cookielen;

    if ( strchr( cookie, '/' ) != NULL ) {
        return( -1 );
    }

    if (( cookielen = strlen( cookie )) >= MAXCOOKIELEN ) {
        return( -1 );
    }

    if (( p = strchr( cookie, '=' )) == NULL ) {
	return( -1 );
    }
    prefixlen = p - cookie;

    if (( cookielen - prefixlen ) <= 2 ) {
	return( -1 );
    }

    if ( hashlen == 0 ) {
	if ( prefix == NULL ) {
	    if ( snprintf( buf, len, "%s", cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	} else {
	    if ( snprintf( buf, len, "%s/%s", prefix, cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	}
    }

    if ( hashlen == 1 ) {
	if ( prefix == NULL ) {
	    if ( snprintf( buf, len, "%c/%s", p[ 1 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	} else {
	    if ( snprintf( buf, len, "%s/%c/%s",
		    prefix, p[ 1 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	}
    }

    if ( hashlen == 2 ) {
	if ( prefix == NULL ) {
	    if ( snprintf( buf, len, "%c%c/%s",
		    p[ 1 ], p[ 2 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	} else {
	    if ( snprintf( buf, len, "%s/%c%c/%s",
		    prefix, p[ 1 ], p[ 2 ], cookie ) >= len ) {
		return( -1 );
	    }
	    return( 0 );
	}
    }
}

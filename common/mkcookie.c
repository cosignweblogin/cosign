#include "config.h"

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
 0, 0, 0, 1, 0, 1, 1, 0,	/*             '+'     '-' '.'     */
 1, 1, 1, 1, 1, 1, 1, 1,	/* '0' '1' '2' '3' '4' '5' '6' '7' */
 1, 1, 0, 0, 0, 1, 0, 0,	/* '8' '9'             '='         */
 1, 1, 1, 1, 1, 1, 1, 1,	/* '@' 'A' 'B' 'C' 'D' 'E' 'F' 'G' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'H' 'I' 'J' 'K' 'L' 'M' 'N' 'O' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'P' 'Q' 'R' 'S' 'T' 'U' 'V' 'W' */
 1, 1, 1, 0, 0, 0, 0, 1,	/* 'X' 'Y' 'Z'                 '_' */
 0, 1, 1, 1, 1, 1, 1, 1,	/*     'a' 'b' 'c' 'd' 'e' 'f' 'g' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'h' 'i' 'j' 'k' 'l' 'm' 'n' 'o' */
 1, 1, 1, 1, 1, 1, 1, 1,	/* 'p' 'q' 'r' 's' 't' 'u' 'v' 'w' */
 1, 1, 1, 0, 0, 0, 0, 0,	/* 'x' 'y' 'z'                     */
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
validchars( char *s )
{
    char	*p;

    for ( p = s; *p != '\0'; p++ ) {
	if ( !valid_tab[ (unsigned char)*p ] ) {
	    return( 0 );
	}
    }
    return( 1 );
}

/*
 * identical to validchars, but also allows characters in ex_chars string
 * in usernames. allows krb5 principals with non-null instances and OpenID
 * user URLs. validchars can't allow slash because it's a field separator
 * in cookies (<cookie_value/timestamp>).
 * 
 * ':' and '~' are included because some OpenID URLs are canonical, and
 * some use ~username in the URLs.
 */
    int
validuser( char *u )
{
    int		rc = 0;
    char	*p, *ex_chars = ":/~";

    for ( p = ex_chars; *p != '\0'; p++ ) {
	valid_tab[ (unsigned char)*p ] = 1;
    }
    rc = validchars( u );
    for ( p = ex_chars; *p != '\0'; p++ ) {
	valid_tab[ (unsigned char)*p ] = 0;
    }

    return( rc );
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
    return( -1 );
}

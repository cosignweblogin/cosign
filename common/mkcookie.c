#include <stdio.h>
#include <openssl/rand.h>

#include "fbase64.h"

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

    if ( RAND_pseudo_bytes( tmp, randbytes ) < 0 ) {
        return( -2 );
    }

    fbase64_e( tmp, randbytes, buf );
    return( 0 );
}

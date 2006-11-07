/*
 * Derived from RSA's:
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USER_INPUT 256

#define _PATH_FAKERS	"/var/ace/mtoken-required-users"

	int
main( int argc, char *argv[] )
{
    int		len;
    char        login[ MAX_USER_INPUT ];
    char        faker[ MAX_USER_INPUT ];
    char        fakeToken[ MAX_USER_INPUT ];
    FILE	*fakers;

    /*
     * login
     * noToken
     */
    if ( fgets( login, sizeof( login ), stdin ) == NULL ) {
        printf( "Internal error: login missing.\n" );
        exit( 1 );
    }
    len = strlen( login );
    if ( login[ len - 1 ] != '\n' ) {
        printf( "Internal error: login too long.\n" );
        exit( 1 );
    }
    login[ len - 1 ] = '\0';

    if ( fgets( fakeToken, sizeof( fakeToken ), stdin ) == NULL ) {
        printf( "Internal error: fakeToken missing.\n" );
        exit( 1 );
    }
    len = strlen( fakeToken );
    if ( fakeToken[ len - 1 ] != '\n' ) {
        printf( "Internal error: fakeToken too long.\n" );
        exit( 1 );
    }
    fakeToken[ len - 1 ] = '\0';

    /*
     * Is login allowed to fakeToken?
     */
    if (( fakers = fopen( _PATH_FAKERS, "r" )) == NULL ) {
	perror( _PATH_FAKERS );
	printf( "Internal error: can't open faker file.\n" );
	exit( 1 );
    }
    while ( fgets( faker, sizeof( faker ), fakers ) != NULL ) {
	len = strlen( faker );
	if ( faker[ len - 1 ] != '\n' ) {
	    printf( "Internal error: faker too long.\n" );
	    exit( 1 );
	}
	faker[ len - 1 ] = '\0';

	if ( strcmp( login, faker ) == 0 ) {
#if 0
	    printf( "You must supply a valid MToken tokencode.\n" );
	    exit( 1 );
#else
	    printf( "mtoken-junk\n" );
	    exit( 0 );
#endif
	}
    }

#if 0
    printf( "mtoken-junk\n" );
    exit( 0 );
#else
    printf( "You must supply a valid MToken tokencode.\n" );
    exit( 1 );
#endif
}

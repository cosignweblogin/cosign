/*
 * Derived from RSA's:
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// in NT this allows using the aceclnt.lib file for linking
#define USE_ACE_AGENT_API_PROTOTYPES
#include "acexport.h"

#define MAX_USER_INPUT 256

	int
main( int argc, char *argv[] )
{
    int		rc = 1, len;
    int         acmRet;
    SDI_HANDLE  SdiHandle = SDI_HANDLE_NONE;
    char        login[ MAX_USER_INPUT ];
    char        passcode[ MAX_USER_INPUT ];

    /*
     * login
     * passcode
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

    if ( fgets( passcode, sizeof( passcode ), stdin ) == NULL ) {
        printf( "Internal error: passcode missing.\n" );
        exit( 1 );
    }
    len = strlen( passcode );
    if ( passcode[ len - 1 ] != '\n' ) {
        printf( "Internal error: passcode too long.\n" );
        exit( 1 );
    }
    passcode[ len - 1 ] = '\0';

    if ( ACM_OK != SD_Init( &SdiHandle )) {
        printf( "Cannot communicate with MToken Server.\n" );
        exit( 1 );
    }

    if ( ACM_OK != SD_Lock( SdiHandle, login )) {
	printf( "Access denied. Name lock failed.\n" );
	SD_Close(SdiHandle);
	exit( 1 );
    }

    switch ( acmRet = SD_Check( SdiHandle, passcode, login )) {
    case ACM_OK:                    // we are in now
	printf( "mtoken\n" );
	SD_Close(SdiHandle);
	exit( 0 );
	
    case ACM_ACCESS_DENIED:         // not this time
	printf( "Access denied.\n" );
	break;
	
    case ACM_INVALID_SERVER:
	printf( "Invalid server.\n" );
	break;
	
    case ACM_NEXT_CODE_REQUIRED:
	printf( "Your MToken is locked.\n" );
	break;
	
    case ACM_NEW_PIN_REQUIRED:
	printf( "Your MToken needs a new PIN.\n" );
	break;
	
    default:
	printf( "Unexpected error from MToken Server.\n");
	break;
    }
    
    SD_Close(SdiHandle);
    exit( 1 );
}

/*
 * Derived from RSA's:
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         /* for getpid() */
#include <time.h>	    /* for timestamp */

// in NT this allows using the aceclnt.lib file for linking
#define USE_ACE_AGENT_API_PROTOTYPES
#include "acexport.h"

#define MAX_USER_INPUT 256
#define _PATH_MTOKEN_LOCK	"/var/run/mtoken.lock"

    int
mtoken_lock( void )
{
    int		fd;

    if (( fd = open( _PATH_MTOKEN_LOCK, O_CREAT|O_RDONLY, 0666 )) < 0 ) {
	perror( _PATH_MTOKEN_LOCK );
	return( -1 );
    }

    if ( flock( fd, LOCK_EX ) < 0 ) {
	perror( _PATH_MTOKEN_LOCK );
	return( -1 );
    }

    return( fd );
}

    char *
mytimestr( char *str, int len )
{
    struct tm   *ptr;
    time_t      tm;

    tm = time( NULL );
    ptr = localtime( &tm );
    strftime( str, len, "%a %b %d %H:%M:%S %Y", ptr );

    return str;
}

	int
main( int argc, char *argv[] )
{
    int		rc = 1, len;
    int         acmRet;
    int		mtlock;
    SDI_HANDLE  SdiHandle = SDI_HANDLE_NONE;
    char        login[ MAX_USER_INPUT ];
    char        passcode[ MAX_USER_INPUT ];
    char        tmStr[ 26 ];

    /*
     * login
     * passcode
     */
    if ( fgets( login, sizeof( login ), stdin ) == NULL ) {
        printf( "Internal error: login missing.\n" );
	fprintf( stderr, "[%s] [mtoken] Internal error: login missing"
		" ( pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), getpid());
        exit( 1 );
    }
    len = strlen( login );
    if ( login[ len - 1 ] != '\n' ) {
        printf( "Internal error: login too long.\n" );
	fprintf( stderr, "[%s] [mtoken] Internal error: login too long"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
        exit( 1 );
    }
    login[ len - 1 ] = '\0';

    if ( fgets( passcode, sizeof( passcode ), stdin ) == NULL ) {
        printf( "Internal error: passcode missing.\n" );
	fprintf( stderr, "[%s] [mtoken] Internal error: passcode missing"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
        exit( 1 );
    }
    len = strlen( passcode );
    if ( passcode[ len - 1 ] != '\n' ) {
        printf( "Internal error: passcode too long.\n" );
	fprintf( stderr, "[%s] [mtoken] Internal error: passcode too long"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
        exit( 1 );
    }
    passcode[ len - 1 ] = '\0';

    if (( mtlock = mtoken_lock()) < 0 ) {
        printf( "Internal error: can't get lock.\n" );
	fprintf( stderr, "[%s] [mtoken] Internal error: can't get lock"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
	exit( 1 );
    }

    if ( ACM_OK != SD_Init( &SdiHandle )) {
        printf( "Cannot communicate with MToken Server.\n" );
	fprintf( stderr, "[%s] [mtoken] SD_Init() failed"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
        exit( 1 );
    }

    if ( ACM_OK != SD_Lock( SdiHandle, login )) {
	printf( "Access denied. Name lock failed.\n" );
	fprintf( stderr, "[%s] [mtoken] SD_Lock() failed"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
	SD_Close(SdiHandle);
	exit( 1 );
    }

    switch ( acmRet = SD_Check( SdiHandle, passcode, login )) {
    case ACM_OK:                    // we are in now
	printf( "mtoken\n" );
	fprintf( stderr, "[%s] [mtoken] ACM_OK ( user = %s, pid = %u )\n",
		    mytimestr( tmStr, sizeof( tmStr )), login, getpid());
	SD_Close(SdiHandle);
	exit( 0 );
	
      case ACM_ACCESS_DENIED:         // not this time
  	printf( "Access denied.\n" );
	fprintf( stderr, "[%s] [mtoken] ACM_ACCESS_DENIED"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
  	break;
  	
      case ACM_INVALID_SERVER:
  	printf( "Invalid server.\n" );
	fprintf( stderr, "[%s] [mtoken] ACM_INVALID_SERVER"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
  	break;
  	
      case ACM_NEXT_CODE_REQUIRED:
	printf( "Your MToken is locked/disabled, please contact an MToken Administrator.\n" );
	fprintf( stderr, "[%s] [mtoken] ACM_NEXT_CODE_REQUIRED"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
  	break;
  	
      case ACM_NEW_PIN_REQUIRED:
  	printf( "Your MToken needs a new PIN.\n" );
	fprintf( stderr, "[%s] [mtoken] ACM_NEW_PIN_REQUIRED"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), login, getpid());
  	break;
  	
      default:
  	printf( "Unexpected error from MToken Server.\n");
	fprintf( stderr, "[%s] [mtoken] Unexpected error, acmRet = %i"
		" ( user = %s, pid = %u )\n",
		mytimestr( tmStr, sizeof( tmStr )), acmRet, login, getpid());
  	break;
    }
    
    SD_Close(SdiHandle);
    exit( 1 );
}

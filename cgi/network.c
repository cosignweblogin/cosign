/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <snet.h>

#include "network.h"

struct timeval          timeout = { 10 * 60, 0 };
extern void            (*logger)( char * );
extern int		errno;
extern int		port;
extern char		*host;

    int
cosign_login( char *cookie, char *ip, char *user, char *realm )
{
    char		*line;
    struct timeval	 tv;
    SNET		*sn;

    if (( sn = connectsn( host, port )) == NULL ) {
	fprintf( stderr, "%s: %d connection failed.\n", host, port );
	return( -2 );
    }

    if ( snet_writef( sn, "LOGIN %s %s %s %s\r\n",
	    cookie, ip, user, realm ) < 0 ) {
	fprintf( stderr, "cosign_login: LOGIN failed\n" );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_login: closesn failed\n" );
	}
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv) ) == NULL ) {
	fprintf( stderr, "cosign_login: %s\n", strerror( errno ));
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_login: closesn failed\n" );
	}
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_login: %s\n", line );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_login: closesn failed\n" );
	}
	return( -1 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cosign_login: closesn failed\n" );
	return( -2 );
    }

    return( 0 );
}
    int
cosign_register( char *cookie, char *ip, char *secant )
{
    char		*line;
    struct timeval	 tv;
    SNET		*sn;

    if (( sn = connectsn( host, port )) == NULL ) {
	fprintf( stderr, "%s: %d connection failed.\n", host, port );
	return( -2 );
    }

    if ( snet_writef( sn, "REGISTER %s %s %s\r\n", cookie, ip, secant ) < 0 ) {
	fprintf( stderr, "cosign_register: register failed\n" );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_register: closesn failed\n" );
	}
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv) ) == NULL ) {
	fprintf( stderr, "cosign_register: %s\n", strerror( errno ));
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_register: closesn failed\n" );
	}
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_register: %s\n", line );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_register: closesn failed\n" );
	}
	if ( *line == '4' ) { /* not logged in */
	    return( 1 );
	}
	return( -1 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cosign_register: closesn failed\n" );
	return( -2 );
    }
    return( 0 );
}

    int
cosign_check( char *cookie )
{
    char		*line;
    struct timeval	 tv;
    SNET		*sn;

    if (( sn = connectsn( host, port )) == NULL ) {
	fprintf( stderr, "%s: %d connection failed.\n", host, port );
	return( -2 );
    }

    if ( snet_writef( sn, "CHECK %s\r\n", cookie ) < 0 ) {
	fprintf( stderr, "cosign_check: check failed\n" );
	return( -1 );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_check: closesn failed\n" );
	}
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv) ) == NULL ) {
	fprintf( stderr, "cosign_check: %s\n", strerror( errno ));
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_check: closesn failed\n" );
	}
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_check: %s\n", line );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_check: closesn failed\n" );
	}
	return( -1 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cosign_check: closesn failed\n" );
	return( -2 );
    }

    return( 0 );
}

    static SNET *
connectsn2( struct sockaddr_in *sin )
{
    int			s;
    char		*line;
    struct timeval      tv;
    SNET                *sn = NULL; 

    if (( s = socket( PF_INET, SOCK_STREAM, NULL )) < 0 ) {
	perror( "socket" );
	exit( 2 );
    }
    if ( connect( s, ( struct sockaddr *)sin,
	    sizeof( struct sockaddr_in ) ) != 0 ) {
	(void)close( s );
	return( NULL );
    }
    if ( ( sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	perror( "snet_attach" );
	exit( 2 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( sn, logger, &tv) ) == NULL ) {
	fprintf( stderr, "connection to %s failed: %s\n",
		inet_ntoa( sin->sin_addr ), strerror( errno ));
	snet_close( sn );
	return( NULL );
    }
    if ( *line !='2' ) {
	fprintf( stderr, "%s\n", line);
	snet_close( sn );
	return( NULL );
    }

    return( sn );
}

    SNET *
connectsn( char *host, int port )
{
    int			i;
    struct hostent      *he;
    struct sockaddr_in  sin;
    SNET                *sn = NULL; 

    memset( &sin, 0, sizeof( struct sockaddr_in ) );
    sin.sin_family = AF_INET;
    sin.sin_port = port;

    /*
     * this code should be enabled only to deal with bugs in
     * the gethostbyname() routine
     */
    if (( sin.sin_addr.s_addr = inet_addr( host )) != -1 ) {
	if (( sn = connectsn2( &sin )) != NULL ) {
	    return( sn );
	}
	fprintf( stderr, "%s: connection failed\n", host );
	exit( 2 );
    }

    if (( he = gethostbyname( host )) == NULL ) {
	fprintf( stderr, "%s: Unknown host\n", host );
	exit( 2 );
    }
    
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	memcpy( &sin.sin_addr.s_addr, he->h_addr_list[ i ],
		( unsigned int)he->h_length );
	if (( sn = connectsn2( &sin )) != NULL ) {
	    return( sn );
	}
    }
    fprintf( stderr, "%s: connection failed\n", host );
    exit( 2 );
}

    int
closesn( SNET *sn )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if ( snet_writef( sn, "QUIT\r\n" ) < 0 ) {
	fprintf( stderr, "close failed: %s\n", strerror( errno ));
	exit( 2 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( sn, logger, &tv ) ) == NULL ) {
	fprintf( stderr, "close failed: %s\n", strerror( errno ));
	exit( 2 );
    }
    if ( *line != '2' ) {
	perror( line );
	return( -1 );
    }
    if ( snet_close( sn ) != 0 ) {
	fprintf( stderr, "close failed: %s\n", strerror( errno ));
	exit( 2 );
    }
    return( 0 );
}

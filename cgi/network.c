/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "network.h"

#define CERTFILE	"/usr/local/umweb/certs/weblogin.cert"
#define CRYPTOFILE	"/usr/local/umweb/certs/weblogin.key"
#define CADIR		"/usr/local/umweb/certs/CA"

struct timeval          timeout = { 10 * 60, 0 };
extern void            (*logger)( char * );
extern int		errno;
extern int		port;
extern char		*host;
SSL_CTX			*ctx;

    int
cosign_login( char *cookie, char *ip, char *user, char *realm, char *krb)
{
    int			fd;
    ssize_t             rr, size = 0;
    char		*line;
    unsigned char	buf[ 8192 ];
    struct stat         st;
    struct timeval	tv;
    SNET		*sn;

    if (( sn = connectsn( host, port )) == NULL ) {
	fprintf( stderr, "%s: %d connection failed.\n", host, port );
	return( -2 );
    }

    if ( snet_writef( sn, "LOGIN %s %s %s %s kerberos\r\n",
	    cookie, ip, user, realm ) < 0 ) {
	fprintf( stderr, "cosign_login: LOGIN failed\n" );
	goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv) ) == NULL ) {
	fprintf( stderr, "cosign_login: %s\n", strerror( errno ));
	goto done;
    }

    if ( *line != '3' ) {
	fprintf( stderr, "cosign_login: %s\n", line );
	goto done;
    }

    if (( fd = open( krb, O_RDONLY, 0 )) < 0 ) {
	perror( krb );
	goto done;
    }

    if ( fstat( fd, &st) < 0 ) {
	perror( krb );
	goto done2;
    }

    size = st.st_size;
    if ( snet_writef( sn, "%d\r\n", (int)st.st_size ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", user, strerror( errno ));
        goto done2;
    }

    while (( rr = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = timeout;
        if ( snet_write( sn, buf, (int)rr, &tv ) != rr ) {
            fprintf( stderr, "login %s failed: %s\n", user,
                strerror( errno ));
            goto done2;
        }
        size -= rr;
    }
    if ( rr < 0 ) {
        perror( krb );
        goto done2;
    }

    /* Check number of bytes sent to server */
    if ( size != 0 ) {
        fprintf( stderr,
            "login %s failed: Sent wrong number of bytes to server\n",
            user );
        goto done2;
    }

    /* End transaction with server */
    if ( snet_writef( sn, ".\r\n" ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", user,
            strerror( errno ));
        goto done2;
    }
    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
        if ( snet_eof( sn )) {
            fprintf( stderr, "login %s failed: Connection closed\n", user );
        } else {
            fprintf( stderr, "login %s failed: %s\n", user, strerror( errno ));
        }
    }
    if ( *line != '2' ) {
        /* Error from server - transaction aborted */
        fprintf( stderr, "cosign_login:%s\n", line );
	goto done2;
    }

    /* Done with server */
    if ( close( fd ) < 0 ) {
        perror( krb );
        return( -1 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cosign_login: closesn failed\n" );
	return( -2 );
    }

    return( 0 );

done2:
    close( fd );

done:
    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cosign_login: closesn failed\n" );
    }
    return ( -1 );
}


    int
cosign_logout( char *cookie, char *ip )
{
    char		*line;
    struct timeval	 tv;
    SNET		*sn;

    if (( sn = connectsn( host, port )) == NULL ) {
	fprintf( stderr, "%s: %d connection failed.\n", host, port );
	return( -2 );
    }

    if ( snet_writef( sn, "LOGOUT %s %s\r\n",
	    cookie, ip ) < 0 ) {
	fprintf( stderr, "cosign_logout: LOGOUT failed\n" );

	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_logout: closesn failed\n" );
	}
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv) ) == NULL ) {
	fprintf( stderr, "cosign_logout: %s\n", strerror( errno ));
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_logout: closesn failed\n" );
	}
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_logout: %s\n", line );
	if (( closesn( sn )) != 0 ) {
	    fprintf( stderr, "cosign_logout: closesn failed\n" );
	}
	return( -1 );
    }

    if (( closesn( sn )) != 0 ) {
	fprintf( stderr, "cosign_logout: closesn failed\n" );
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
connectsn2( struct sockaddr_in *sin, char *host )
{
    int			s;
    char		*line, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;
    SNET                *sn = NULL; 


    SSL_load_error_strings();
    SSL_library_init();
    if (( ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
        fprintf( stderr, "SSL_CTX_new: %s\n",
                ERR_error_string( ERR_get_error(), NULL ));
        exit( 1 );
    }
    if ( SSL_CTX_use_PrivateKey_file( ctx,
            CRYPTOFILE, SSL_FILETYPE_PEM ) != 1 ) {
        fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
                CRYPTOFILE, ERR_error_string( ERR_get_error(), NULL ));
        exit( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( ctx, CERTFILE ) != 1 ) {
        fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
                CERTFILE, ERR_error_string( ERR_get_error(), NULL ));
        exit( 1 );
    }
    if ( SSL_CTX_check_private_key( ctx ) != 1 ) {
        fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
                ERR_error_string( ERR_get_error(), NULL ));
        exit( 1 );
    }
    if ( SSL_CTX_load_verify_locations( ctx, NULL, CADIR ) != 1 ) {
        fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
                CRYPTOFILE, ERR_error_string( ERR_get_error(), NULL ));
        exit( 1 );
    }
    SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, NULL );

    if (( s = socket( PF_INET, SOCK_STREAM, NULL )) < 0 ) {
	perror( "socket" );
	exit( 2 );
    }
    if ( connect( s, (struct sockaddr *)sin,
	    sizeof( struct sockaddr_in ) ) != 0 ) {
	(void)close( s );
	return( NULL );
    }
    if (( sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	perror( "snet_attach" );
	exit( 2 );
    }
    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "connection to %s failed: %s\n",
		inet_ntoa( sin->sin_addr ), strerror( errno ));
	goto done;
    }
    if ( *line !='2' ) {
	fprintf( stderr, "connectsn2: %s\n", line);
	goto done;
    }

    if ( snet_writef( sn, "STARTTLS\r\n" ) < 0 ) {
        fprintf( stderr, "connec_sn2: starttls failed\n" );
        goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
        fprintf( stderr, "connectsn2: snet_getline_multi failed\n" );
        goto done;
    }
    if ( *line != '2' ) {
        fprintf( stderr, "connectsn2: %s\n", line );
        goto done;
    }

    if ( snet_starttls( sn, ctx, 0 ) != 1 ) {
        fprintf( stderr, "snet_starttls: %s\n",
                ERR_error_string( ERR_get_error(), NULL ));
        goto done;
    }

    if (( peer = SSL_get_peer_certificate( sn->sn_ssl )) == NULL ) {
        fprintf( stderr, "no certificate\n" );
        goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
            buf, sizeof( buf ));

    if ( strcmp( buf, host ) != 0 ) {
	fprintf( stderr, "CERT CN:%s & host:%s don't match\n", buf, host );
	X509_free( peer );
	goto done;
    }
    X509_free( peer );

    return( sn );

done:
     if ( snet_close( sn ) != 0 ) {
        fprintf( stderr, "connectsn2: snet_close failed\n" );
    }
    return( NULL );

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
	if (( sn = connectsn2( &sin, host )) != NULL ) {
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
	if (( sn = connectsn2( &sin, host )) != NULL ) {
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

/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#define OPENSSL_DISABLE_OLD_DES_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "cosigncgi.h"
#include "network.h"

static void (*logger)( char * ) = NULL;
static struct timeval		timeout = { 10 * 60, 0 };
extern int	errno;
SSL_CTX		*ctx;

    struct connlist *
connlist_setup( char *host, int port )
{

    int			i;
    struct hostent	*he;
    struct connlist	*head, *new, **tail;

    if (( he = gethostbyname( host )) == NULL ) {
        fprintf( stderr, "%s no wanna give hostnames\n", host );
        return( NULL );
    }
    tail = &head;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
        if (( new = ( struct connlist * ) malloc( sizeof( struct connlist )))
		 == NULL ) {
            perror( "connlist build" );
	    return( NULL );
        }

        memset( &new->conn_sin, 0, sizeof( struct sockaddr_in ));
        new->conn_sin.sin_family = AF_INET;
        new->conn_sin.sin_port = port;
        memcpy( &new->conn_sin.sin_addr.s_addr,
                he->h_addr_list[ i ], (unsigned int)he->h_length );
        new->conn_sn = NULL;
        *tail = new;
        tail = &new->conn_next;   
    }
    *tail = NULL;

    return( head );

}

    void
ssl_setup( void )
{

    char	*certfile = _COSIGN_TLS_CERT;
    char	*cryptofile = _COSIGN_TLS_KEY;
    char	*cadir = _COSIGN_TLS_CADIR;

    if ( access( cryptofile, R_OK ) != 0 ) {
        perror( cryptofile );
        exit( 1 );
    }

    if ( access( certfile, R_OK ) != 0 ) {
        perror( certfile );
        exit( 1 );
    }

    if ( access( cadir, R_OK ) != 0 ) {
        perror( cadir );
        exit( 1 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if (( ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	fprintf( stderr, "SSL_CTX_new: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }

    if ( SSL_CTX_use_PrivateKey_file( ctx, cryptofile, SSL_FILETYPE_PEM )
	    != 1 ) {
	fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	exit( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( ctx, certfile ) != 1) {
	fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	exit( 1 );
    }
    if ( SSL_CTX_check_private_key( ctx ) != 1 ) {
	fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }

    if ( SSL_CTX_load_verify_locations( ctx, NULL, cadir ) != 1 ) {
	fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	exit( 1 );
    }
    SSL_CTX_set_verify( ctx,
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return;
}


    int
cosign_login( struct connlist *conn, char *cookie, char *ip, char *user,
	char *realm, char *krb )
{
    int			fd = 0;
    ssize_t             rr, size = 0;
    char		*line;
    unsigned char	buf[ 8192 ];
    struct stat         st;
    struct timeval	tv;

    /* connect thingie */ 

    /* if we're doing BasicAuth or PAM we might not have a ticket */
    if ( krb == NULL ) {
	if ( snet_writef( conn->conn_sn, "LOGIN %s %s %s %s\r\n",
		cookie, ip, user, realm ) < 0 ) {
	    fprintf( stderr, "cosign_login: LOGIN failed\n" );
	    goto done;
	}
    } else {
	if ( snet_writef( conn->conn_sn, "LOGIN %s %s %s %s kerberos\r\n",
		cookie, ip, user, realm ) < 0 ) {
	    fprintf( stderr, "cosign_login: LOGIN failed\n" );
	    goto done;
	}
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_login: %s\n", strerror( errno ));
	goto done;
    }

    if ( krb == NULL ) {
	/* skip ticket stuff */
	goto finish;
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
    if ( snet_writef( conn->conn_sn, "%d\r\n", (int)st.st_size ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", user, strerror( errno ));
        goto done2;
    }

    while (( rr = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = timeout;
        if ( snet_write( conn->conn_sn, buf, (int)rr, &tv ) != rr ) {
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
    if ( snet_writef( conn->conn_sn, ".\r\n" ) < 0 ) {
        fprintf( stderr, "login %s failed: %s\n", user,
            strerror( errno ));
        goto done2;
    }
    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
        if ( snet_eof( conn->conn_sn )) {
            fprintf( stderr, "login %s failed: Connection closed\n", user );
        } else {
            fprintf( stderr, "login %s failed: %s\n", user, strerror( errno ));
        }
    }

finish:
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
    /* close */

    return( 0 );

done2:
    close( fd );

done:
    /* close */
    return ( -1 );
}


    int
cosign_logout( struct connlist *conn, char *cookie, char *ip )
{
    char		*line;
    struct timeval	 tv;

    /* conn code loopy */

    if ( snet_writef( conn->conn_sn, "LOGOUT %s %s\r\n",
	    cookie, ip ) < 0 ) {
	fprintf( stderr, "cosign_logout: LOGOUT failed\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_logout: %s\n", strerror( errno ));
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_logout: %s\n", line );
	return( -1 );
    }

    return( 0 );
}


    int
cosign_register( struct connlist *conn, char *cookie, char *ip, char *scookie )
{
    char		*line;
    struct timeval	 tv;

    /* loopy */
    if ( snet_writef( conn->conn_sn, "REGISTER %s %s %s\r\n", cookie, ip, scookie ) < 0 ) {
	fprintf( stderr, "cosign_register: register failed\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_register: %s\n", strerror( errno ));
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_register: %s\n", line );
	if ( *line == '4' ) { /* not logged in */
	    return( 1 );
	}
	return( -1 );
    }

    return( 0 );
}


    int
cosign_check( struct connlist *conn, char *cookie )
{
    char		*line;
    struct timeval	 tv;

    /* loopy */

    if ( snet_writef( conn->conn_sn, "CHECK %s\r\n", cookie ) < 0 ) {
	fprintf( stderr, "cosign_check: check failed\n" );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	fprintf( stderr, "cosign_check: %s\n", strerror( errno ));
	return( -1 );
    }

    if ( *line != '2' ) {
	fprintf( stderr, "cosign_check: %s\n", line );
	return( -1 );
    }


    return( 0 );
}

    int
connect_sn( struct connlist *conn, char *host )
{
    int			s, err = -1;
    char		*line, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;

    if (( s = socket( PF_INET, SOCK_STREAM, (int)NULL )) < 0 ) {
	    return( -1 );
    }
    if ( connect( s, ( struct sockaddr *)&conn->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	syslog( LOG_ERR, "connect: %m" );
	(void)close( s );
	return( -1 );
    }

    if (( conn->conn_sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	syslog( LOG_ERR, "connect_sn: snet_attach failed" );
	(void)close( s );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	syslog( LOG_ERR, "connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	syslog( LOG_ERR, "connect_sn: %s", line );
	goto done;
    }
    if ( snet_writef( conn->conn_sn, "STARTTLS\r\n" ) < 0 ) {
	syslog( LOG_ERR, "connect_sn: starttls is kaplooey" );
	goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( conn->conn_sn, logger, &tv )) == NULL ) {
	syslog( LOG_ERR, "connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	syslog( LOG_ERR, "connect_sn: %s", line );
	goto done;
    }

    if ( snet_starttls( conn->conn_sn, ctx, 0 ) != 1 ) {
	syslog( LOG_ERR, "snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	err = -2;
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( conn->conn_sn->sn_ssl )) == NULL ) {
	syslog( LOG_ERR, "no certificate" );
	err = -2;
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));
    /* cn and host must match */
    if ( strcmp( buf, host ) != 0 ) {
	syslog( LOG_ERR, "cn=%s & host=%s don't match!", buf, host );
	X509_free( peer );
	err = -2;
	goto done;
    }
    X509_free( peer );
    return( 0 );
done:
    if ( snet_close( conn->conn_sn ) != 0 ) {
	syslog( LOG_ERR, "connect_sn: snet_close failed" );
    }
    conn->conn_sn = NULL;

    return( err );
}

   int 
close_sn( struct connlist *conn )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if (( snet_writef( conn->conn_sn, "QUIT\r\n" )) <  0 ) {
	syslog( LOG_ERR, "close_sn: snet_writef failed" );
	return( -1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( conn->conn_sn, logger, &tv ) ) == NULL ) {
	syslog( LOG_ERR, "close_sn: snet_getline_multi failed" );
	return( -1 );
    }
    if ( *line != '2' ) {
	syslog( LOG_ERR, "close_sn: %s", line  );
    }
    if ( snet_close( conn->conn_sn ) != 0 ) {
	syslog( LOG_ERR, "close_sn: snet_close failed" );
    }
    conn->conn_sn = NULL;

    return( 0 );
}

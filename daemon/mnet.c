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

#include "argcargv.h"
#include "rate.h"
#include "monster.h"

static void (*logger)( char * ) = NULL;

extern struct timeval	cosign_net_timeout;

    int
connect_sn( struct connlist *cl, SSL_CTX *ctx, char *host )
{
    int			s, err = -1;
    char		*line, buf[ 1024 ];
    X509		*peer;
    struct timeval      tv;

    if (( s = socket( PF_INET, SOCK_STREAM, (int)NULL )) < 0 ) {
	    return( -1 );
    }
    if ( connect( s, ( struct sockaddr *)&cl->cl_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
	syslog( LOG_ERR, "connect: %m" );
	(void)close( s );
	return( -1 );
    }

    if (( cl->cl_sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	syslog( LOG_ERR, "connect_sn: snet_attach failed" );
	(void)close( s );
	return( -1 );
    }

    tv = cosign_net_timeout;
    if (( line = snet_getline_multi( cl->cl_sn, logger, &tv )) == NULL ) {
	syslog( LOG_ERR, "connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	syslog( LOG_ERR, "connect_sn: %s", line );
	goto done;
    }
    if ( snet_writef( cl->cl_sn, "STARTTLS\r\n" ) < 0 ) {
	syslog( LOG_ERR, "connect_sn: starttls is kaplooey" );
	goto done;
    }

    tv = cosign_net_timeout;
    if (( line = snet_getline_multi( cl->cl_sn, logger, &tv )) == NULL ) {
	syslog( LOG_ERR, "connect_sn: snet_getline_multi failed" );
	goto done;
    }
    if ( *line != '2' ) {
	syslog( LOG_ERR, "connect_sn: %s", line );
	goto done;
    }

    if ( snet_starttls( cl->cl_sn, ctx, 0 ) != 1 ) {
	syslog( LOG_ERR, "snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	err = -2;
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( cl->cl_sn->sn_ssl )) == NULL ) {
	syslog( LOG_ERR, "no certificate" );
	err = -2;
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));
    /* cn and host must match */
    X509_free( peer );
    if ( strcasecmp( buf, host ) != 0 ) {
	syslog( LOG_ERR, "cn=%s & host=%s don't match!", buf, host );
	err = -2;
	goto done;
    }
    return( 0 );
done:
    if ( snet_close( cl->cl_sn ) != 0 ) {
	syslog( LOG_ERR, "connect_sn: snet_close failed" );
    }
    cl->cl_sn = NULL;

    return( err );
}


   int 
close_sn( struct connlist *cl )
{
    char		*line;
    int			err = 0;
    struct timeval      tv;

    /* Close network connection */
    if (( snet_writef( cl->cl_sn, "QUIT\r\n" )) <  0 ) {
	syslog( LOG_ERR, "close_sn: snet_writef failed" );
	err = -1;
	goto done;
    }

    tv = cosign_net_timeout;
    if ( ( line = snet_getline_multi( cl->cl_sn, logger, &tv ) ) == NULL ) {
	syslog( LOG_ERR, "close_sn: snet_getline_multi failed" );
	err = -1;
	goto done;
    }
    if ( *line != '2' ) {
	syslog( LOG_ERR, "close_sn: %s", line  );
    }

done:
    if ( snet_close( cl->cl_sn ) != 0 ) {
	syslog( LOG_ERR, "close_sn: snet_close failed" );
    }
    cl->cl_sn = NULL;

    return( err );
}

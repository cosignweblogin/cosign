/*
 * Copyright (c) 1995,2001 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <inttypes.h>

#include <netinet/in.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif TLS


#ifdef __STDC__
#include <stdarg.h>
#else __STDC__
#include <varargs.h>
#endif __STDC__

#include "snet.h"

#define SNET_BUFLEN	1024

#define SNET_BOL	0
#define SNET_FUZZY	1
#define SNET_IN		2

#define SNET_EOF	(1<<0)
#define SNET_TLS	(1<<1)

static int snet_readread ___P(( SNET *, char *, int, struct timeval * ));

/*
 * This routine is necessary, since snet_getline() doesn't differentiate
 * between NULL => EOF and NULL => connection dropped (or some other error).
 */
    int
snet_eof( sn )
    SNET		*sn;
{
    return ( sn->sn_flag & SNET_EOF );
}

    SNET *
snet_attach( fd, max )
    int		fd;
    int		max;
{
    SNET		*sn;

    if (( sn = (SNET *)malloc( sizeof( SNET ))) == NULL ) {
	return( NULL );
    }
    sn->sn_fd = fd;
    if (( sn->sn_rbuf = (char *)malloc( SNET_BUFLEN )) == NULL ) {
	free( sn );
	return( NULL );
    }
    sn->sn_rbuflen = SNET_BUFLEN;
    sn->sn_rstate = SNET_BOL;
    sn->sn_rcur = sn->sn_rend = sn->sn_rbuf;
    sn->sn_maxlen = max;

    if (( sn->sn_wbuf = (char *)malloc( SNET_BUFLEN )) == NULL ) {
	free( sn->sn_rbuf );
	free( sn );
	return( NULL );
    }
    sn->sn_wbuflen = SNET_BUFLEN;

    sn->sn_flag = 0;

    return( sn );
}

    SNET *
snet_open( path, flags, mode, max )
    char	*path;
    int		flags;
    int		mode;
{
    int		fd;

    if (( fd = open( path, flags, mode )) < 0 ) {
	return( NULL );
    }
    return( snet_attach( fd, max ));
}

    int
snet_close( sn )
    SNET		*sn;
{
    free( sn->sn_wbuf );
    free( sn->sn_rbuf );
    if ( close( sn->sn_fd ) < 0 ) {
	return( -1 );
    }
    free( sn );
    return( 0 );
}

#ifdef TLS
    char *
snet_inittls( sn, server, devrand, cryptofile )
    SNET		*sn;
    int			server;
    int			devrand;
    char		*cryptofile;
{
    char		randfile[ MAXPATHLEN ];
    STACK_OF(X509_NAME)	*certnames;

    SSL_load_error_strings();
    SSL_library_init();
    if ( !devrand ) {
	if ( RAND_file_name( randfile, sizeof( randfile )) == NULL ) {
	    return( ERR_error_string( ERR_get_error(), NULL ));
	}
	if ( RAND_load_file( randfile, -1 ) <= 0 ) {
	    return( ERR_error_string( ERR_get_error(), NULL ));
	}
	if ( RAND_write_file( randfile ) < 0 ) {
	    return( ERR_error_string( ERR_get_error(), NULL ));
	}
    }

    if (( sn->sn_sslctx = SSL_CTX_new( server ? SSLv23_server_method() :
	    SSLv23_client_method())) == NULL ) {
	return( ERR_error_string( ERR_get_error(), NULL ));
    }
    if ( cryptofile ) {
	if ( server ) {
	    /* this is really supposed to be SSL_CTX_load_verify_locations */
	    if (( certnames = SSL_load_client_CA_file( cryptofile )) == NULL ) {
		return( "SSL_load_client_CA_file" );
		return( ERR_error_string( ERR_get_error(), NULL ));
	    }
	    SSL_CTX_set_client_CA_list( sn->sn_sslctx, certnames );
	}

	if ( SSL_CTX_use_PrivateKey_file( sn->sn_sslctx,
		cryptofile, SSL_FILETYPE_PEM ) != 1 ) {
	    return( "SSL_CTX_use_PrivateKey_file" );
	    return( ERR_error_string( ERR_get_error(), NULL ));
	}

	if ( SSL_CTX_use_certificate_chain_file( sn->sn_sslctx,
		cryptofile ) != 1 ) {
	    return( "SSL_CTX_use_certificate_chain_file" );
	    return( ERR_error_string( ERR_get_error(), NULL ));
	}
	if ( SSL_CTX_check_private_key( sn->sn_sslctx ) != 1 ) {
	    return( "SSL_CTX_check_private_key" );
	    return( ERR_error_string( ERR_get_error(), NULL ));
	}
    }
    return( NULL );
}

    char *
snet_starttls( sn, server )
    SNET		*sn;
    int			server;
{
    int			rc;

    if (( sn->sn_ssl = SSL_new( sn->sn_sslctx )) == NULL ) {
	return( "SSL_new" );
    }
    if ( SSL_set_fd( sn->sn_ssl, sn->sn_fd ) != 1 ) {
	return( "SSL_set_fd" );
    }
    if ( server ) {
	rc = SSL_accept( sn->sn_ssl );
    } else {
	rc = SSL_connect( sn->sn_ssl );
    }
    if ( rc != 1 ) {
	return( ERR_error_string( ERR_get_error(), NULL ));
    }
    sn->sn_flag |= SNET_TLS;
    return( 0 );
}
#endif TLS

/*
 * Just like fprintf, only use the SNET header to get the fd, and use
 * snet_write() to move the data.
 *
 * Todo: %f, *, . and, -
 */
    int
#ifdef __STDC__
snet_writef( SNET *sn, char *format, ... )
#else __STDC__
snet_writef( sn, format, va_alist )
    SNET			*sn;
    char		*format;
    va_dcl
#endif __STDC__
{
    va_list		vl;
    char		dbuf[ 128 ], *p, *dbufoff;
    int			d, len;
    char		*cur, *end;

#ifdef __STDC__
    va_start( vl, format );
#else __STDC__
    va_start( vl );
#endif __STDC__

#define SNET_WRITEFGROW(x)						\
	    while ( cur + (x) > end ) {					\
		if (( sn->sn_wbuf = (char *)realloc( sn->sn_wbuf,	\
			sn->sn_wbuflen + SNET_BUFLEN )) == NULL ) {	\
		    abort();						\
		}							\
		cur = sn->sn_wbuf + sn->sn_wbuflen - ( end - cur );	\
		sn->sn_wbuflen += SNET_BUFLEN;				\
		end = sn->sn_wbuf + sn->sn_wbuflen;			\
	    }		

    cur = sn->sn_wbuf;
    end = sn->sn_wbuf + sn->sn_wbuflen;

    for ( ; *format; format++ ) {
	dbufoff = dbuf + sizeof( dbuf );

	if ( *format != '%' ) {
	    SNET_WRITEFGROW( 1 );
	    *cur++ = *format;
	} else {
	    switch ( *++format ) {
	    case 's' :
		p = va_arg( vl, char * );
		len = strlen( p );
		SNET_WRITEFGROW( len );
		strcpy( cur, p );
		cur += strlen( p );
		break;

	    case 'c' :
		SNET_WRITEFGROW( 1 );
		*cur++ = va_arg( vl, int );
		break;

	    case 'd' :
		d = va_arg( vl, int );
		p = dbufoff;
		do {
		    if ( --dbufoff < dbuf ) {
			abort();
		    }
		    *dbufoff = '0' + ( d % 10 );
		    d /= 10;
		} while ( d );
		len = p - dbufoff;
		SNET_WRITEFGROW( len );
		strncpy( cur, dbufoff, len );
		cur += len;
		break;

	    case 'o' :
		d = va_arg( vl, int );
		p = dbufoff;
		do {
		    if ( --dbufoff < dbuf ) {
			abort();
		    }
		    *dbufoff = '0' + ( d & 0007 );
		    d = d >> 3;
		} while ( d );
		len = p - dbufoff;
		SNET_WRITEFGROW( len );
		strncpy( cur, dbufoff, len );
		cur += len;
		break;

	    case 'x' :
		d = va_arg( vl, int );
		p = dbufoff;
		do {
		    char	hexalpha[] = "0123456789abcdef";

		    if ( --dbufoff < dbuf ) {
			abort();
		    }
		    *dbufoff = hexalpha[ d & 0x0f ];
		    d = d >> 4;
		} while ( d );
		SNET_WRITEFGROW( len );
		strncpy( cur, dbufoff, len );
		cur += len;
		break;

	    default :
		SNET_WRITEFGROW( 2 );
		*cur++ = '%';
		*cur++ = *format;
		break;
	    }
	}
    }

    va_end( vl );

    return( snet_write( sn, sn->sn_wbuf, cur - sn->sn_wbuf, 0 ));
}

/*
 * Should we set non-blocking IO?  Do we need to bother?
 * We'll leave tv in here now, so that we don't have to change the call
 * later.  It's currently ignored.
 */
    int
snet_write( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    int			len;
    struct timeval	*tv;
{
    if ( sn->sn_flag & SNET_TLS ) {
#ifdef TLS
	return( SSL_write( sn->sn_ssl, buf, len ));
#else
	return( -1 );
#endif TLS
    } else {
	return( write( snet_fd( sn ), buf, len ));
    }
}

    static int
snet_readread( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    int			len;
    struct timeval	*tv;
{
#ifndef linux
    struct timeval	tv_begin, tv_end;
#endif linux
    fd_set		fds;
    int			rc;
    extern int		errno;

    if ( tv ) {
	FD_ZERO( &fds );
	FD_SET( snet_fd( sn ), &fds );
#ifndef linux
	if ( gettimeofday( &tv_begin, NULL ) < 0 ) {
	    return( -1 );
	}
#endif linux
	/* time out case? */
	if ( select( snet_fd( sn ) + 1, &fds, NULL, NULL, tv ) < 0 ) {
	    return( -1 );
	}
	if ( FD_ISSET( snet_fd( sn ), &fds ) == 0 ) {
	    errno = ETIMEDOUT;
	    return( -1 );
	}
#ifndef linux
	if ( gettimeofday( &tv_end, NULL ) < 0 ) {
	    return( -1 );
	}

	if ( tv_begin.tv_usec > tv_end.tv_usec ) {
	    tv_end.tv_usec += 1000000;
	    tv_end.tv_sec -= 1;
	}
	if (( tv->tv_usec -= ( tv_end.tv_usec - tv_begin.tv_usec )) < 0 ) {
	    tv->tv_usec += 1000000;
	    tv->tv_sec -= 1;
	}
	if (( tv->tv_sec -= ( tv_end.tv_sec - tv_begin.tv_sec )) < 0 ) {
	    errno = ETIMEDOUT;
	    return( -1 );
	}
#endif linux
    }

    if ( sn->sn_flag & SNET_TLS ) {
#ifdef TLS
	rc = SSL_read( sn->sn_ssl, buf, len );
#else TLS
	rc = -1;
#endif TLS
    } else {
	rc = read( snet_fd( sn ), buf, len );
    }
    if ( rc == 0 ) {
	sn->sn_flag = SNET_EOF;
    }

    return( rc );
}

/*
 * External entry point for reading with the snet library.  Compatible
 * with snet_getline()'s buffering.
 */
    int
snet_read( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    int			len;
    struct timeval	*tv;
{
    int			rc;

    /*
     * If there's data already buffered, make sure it's not left over
     * from snet_getline(), and then return whatever's left.
     * Note that snet_getline() calls snet_readread().
     */
    if ( sn->sn_rcur < sn->sn_rend ) {
	if (( *sn->sn_rcur == '\n' ) && ( sn->sn_rstate == SNET_FUZZY )) {
	    sn->sn_rstate = SNET_BOL;
	    sn->sn_rcur++;
	}
	if ( sn->sn_rcur < sn->sn_rend ) {
#ifndef min
#define min(a,b)	(((a)<(b))?(a):(b))
#endif min
	    rc = min( sn->sn_rend - sn->sn_rcur, len );
	    memcpy( buf, sn->sn_rcur, rc );
	    sn->sn_rcur += rc;
	    return( rc );
	}
    }

    return( snet_readread( sn, buf, len, tv ));
}

/*
 * Get a null-terminated line of input, handle CR/LF issues.
 * Note that snet_getline() returns information from a common area which
 * may be overwritten by subsequent calls.
 */
    char *
snet_getline( sn, tv )
    SNET		*sn;
    struct timeval	*tv;
{
    char		*eol, *line;
    int			rc;
    extern int		errno;

    for ( eol = sn->sn_rcur; ; eol++) {
	if ( eol >= sn->sn_rend ) {				/* fill */
	    /* pullup */
	    if ( sn->sn_rcur > sn->sn_rbuf ) {
		if ( sn->sn_rcur < sn->sn_rend ) {
		    memcpy( sn->sn_rbuf, sn->sn_rcur,
			    (unsigned)( sn->sn_rend - sn->sn_rcur ));
		}
		eol = sn->sn_rend = sn->sn_rbuf + ( sn->sn_rend - sn->sn_rcur );
		sn->sn_rcur = sn->sn_rbuf;
	    }

	    /* expand */
	    if ( sn->sn_rend == sn->sn_rbuf + sn->sn_rbuflen ) {
		if ( sn->sn_maxlen != 0 && sn->sn_rbuflen >= sn->sn_maxlen ) {
		    errno = ENOMEM;
		    return( NULL );
		}
		if (( sn->sn_rbuf = (char *)realloc( sn->sn_rbuf,
			sn->sn_rbuflen + SNET_BUFLEN )) == NULL ) {
		    exit( 1 );
		}
		sn->sn_rbuflen += SNET_BUFLEN;
		eol = sn->sn_rend = sn->sn_rbuf + ( sn->sn_rend - sn->sn_rcur );
		sn->sn_rcur = sn->sn_rbuf;
	    }

	    if (( rc = snet_readread( sn, sn->sn_rend,
		    sn->sn_rbuflen - ( sn->sn_rend - sn->sn_rbuf ),
		    tv )) < 0 ) {
		return( NULL );
	    }
	    if ( rc == 0 ) {	/* EOF */
		return( NULL );
	    }
	    sn->sn_rend += rc;
	}

	if ( *eol == '\r' || *eol == '\0' ) {
	    sn->sn_rstate = SNET_FUZZY;
	    break;
	}
	if ( *eol == '\n' ) {
	    if ( sn->sn_rstate == SNET_FUZZY ) {
		sn->sn_rstate = SNET_BOL;
		sn->sn_rcur = eol + 1;
		continue;
	    }
	    sn->sn_rstate = SNET_BOL;
	    break;
	}
	sn->sn_rstate = SNET_IN;
    }

    *eol = '\0';
    line = sn->sn_rcur;
    sn->sn_rcur = eol + 1;
    return( line );
}

    char * 
snet_getline_multi( sn, logger, tv )
    SNET		*sn;
    void		(*logger)( char * );
    struct timeval	*tv;
{
    char		*line; 

    do {
	if (( line = snet_getline( sn, tv )) == NULL ) {
	    return ( NULL );
	}

	if ( logger != NULL ) {
	    (*logger)( line );
	}

	if ( strlen( line ) < 3 ) {
	    return( NULL );
	}

	if ( !isdigit( (int)line[ 0 ] ) ||
		!isdigit( (int)line[ 1 ] ) ||
		!isdigit( (int)line[ 2 ] )) {
	    return( NULL );
	}

	if ( line[ 3 ] != '\0' &&
		line[ 3 ] != ' ' &&
		line [ 3 ] != '-' ) {
	    return ( NULL );
	}

    } while ( line[ 3 ] == '-' );

    return( line );
}

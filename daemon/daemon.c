 /*
  * Copyright (c) 1999 Regents of The University of Michigan.
  * All Rights Reserved.  See LICENSE.
  */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "logname.h"
#include "command.h"
#include "config.h"
#include "monster.h"
#include "pusher.h"


int		debug = 0;
int		backlog = 5;
int		pusherpid;

extern char	*cosign_version;
int		tlsopt = 0;
char		*cosign_dir = _COSIGN_DIR;
char		*cosign_conf = _COSIGN_CONF;
SSL_CTX		*ctx = NULL;


void		hup ___P(( int ));
void		chld ___P(( int ));
int		main ___P(( int, char *av[] ));

    void
hup( sig )
    int			sig;
{
    syslog( LOG_INFO, "reload %s", cosign_version );
    if ( chosts_read( cosign_conf ) < 0 ) {
	syslog( LOG_ERR, "%s: re-read failed", cosign_conf );
	exit( 1 );
    }

    if ( kill( pusherpid, sig ) < 0 ) {
	syslog( LOG_CRIT, "kill pusherpid: %m" );
	exit( 1 );
    }

    return;
}

    void
chld( sig )
    int			sig;
{
    int			pid, status;
    extern int		errno;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	if ( WIFEXITED( status )) {
	    if ( WEXITSTATUS( status )) {
		syslog( LOG_ERR, "child %d exited with %d", pid,
			WEXITSTATUS( status ));
	    }
	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "child %d died on signal %d", pid,
		    WTERMSIG( status ));
	} else {
	    syslog( LOG_ERR, "child %d died", pid );
	}
	if ( pid == pusherpid ) {
	    syslog( LOG_CRIT, "pusherpid %d died!", pusherpid );
	    exit( 1 );
	}
    }

    if ( pid < 0 && errno != ECHILD ) {
	syslog( LOG_ERR, "wait3: %m" );
	exit( 1 );
    }
    return;
}



    int
main( ac, av )
    int		ac;
    char	*av[];
{
    struct sigaction	sa, osahup, osachld;
    struct sockaddr_in	sin;
    struct servent	*se;
    SNET		*pushersn = NULL;
    int			c, s, err = 0, fd, sinlen;
    int			dontrun = 0, fds[ 2 ];
    int			reuseaddr = 1;
    char		*prog;
    char		*replhost = NULL;
    char		*cryptofile = _COSIGN_TLS_KEY;
    char		*certfile = _COSIGN_TLS_CERT;
    char		*cadir = _COSIGN_TLS_CADIR;
    int                 facility = _COSIGN_LOG;
    unsigned short	port = 0;
    extern int		optind;
    extern char		*optarg;

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

    while (( c = getopt( ac, av, "b:c:dD:h:L:p:VXx:y:z:" )) != -1 ) {
	switch ( c ) {
	case 'b' :		/* listen backlog */
	    backlog = atoi( optarg );
	    break;

	case 'c' :		/* config file */
	    cosign_conf = optarg;
	    break;

	case 'd' :		/* debug */
	    debug++;
	    break;

	case 'D' :		/* directory to store cookies*/
	    cosign_dir = optarg;
	    break;

	case 'h' :		/* host to replicate to*/
	    replhost = optarg;
	    break;

	case 'L' :              /* syslog facility */
	    if (( facility = syslogname( optarg )) == -1 ) {
		fprintf( stderr, "%s: %s: unknown syslog facility\n",
			prog, optarg );
		exit( 1 );
	    }
	    break;

	case 'p' :		/* TCP port */
	    port = htons( atoi( optarg ));
	    break;

	case 'V' :		/* version */
	    printf( "%s\n", cosign_version );
	    exit( 0 );

	case 'X' :		/* no required tls/ssl for debugging */
	    tlsopt = 1;
	    break;

	case 'x' :		/* ca dir */
	    cadir = optarg;
	    break;
	
	case 'y' :		/* cert */
	    certfile = optarg;
	    break;
	
	case 'z' :		/* private key file */
	    cryptofile = optarg;
	    break;
	
	default :
	    err++;
	}
    }

    if ( err || optind != ac ) {
	fprintf( stderr, "Usage: cosignd [ -dV ] [ -b backlog ] ");
	fprintf( stderr, "[ -c conf file ] [ -D database dir ] " );
	fprintf( stderr, "[ -L syslog facility] " );
	fprintf( stderr, "[ -p port ] [ -x ca dir ] " );
	fprintf( stderr, "[ -y cert file] [ -z private key file ]\n" );
	exit( 1 );
    }

    /*
     * Read config file before chdir(), in case config file is relative path.
     */

    if ( chosts_read( cosign_conf ) < 0 ) {
	exit( 1 );
    }

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

    if ( cryptofile != NULL ) {
	SSL_load_error_strings();
	SSL_library_init();

	if (( ctx = SSL_CTX_new( SSLv23_method())) == NULL ) {
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
    }


    if ( dontrun ) {
	exit( 0 );
    }

    if ( port == 0 ) {
	if (( se = getservbyname( "cosign", "tcp" )) == NULL ) {
	    fprintf( stderr, "%s: can't find cosign service\n"
		    "%s: continuing...\n", prog, prog );
	    port = htons( 6663 );
	} else {
	    port = se->s_port;
	}
    }

    /*
     * Set up listener.
     */
    if (( s = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
	perror( "socket" );
	exit( 1 );
    }
    if ( reuseaddr ) {
	if ( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (void*)&reuseaddr,
		sizeof( int )) < 0 ) {
	    perror("setsockopt");
	}
    }

    memset( &sin, 0, sizeof( struct sockaddr_in ));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = port;
    if ( bind( s, (struct sockaddr *)&sin, sizeof( struct sockaddr_in )) < 0 ) {
	perror( "bind" );
	exit( 1 );
    }
    if ( listen( s, backlog ) < 0 ) {
	perror( "listen" );
	exit( 1 );
    }

    if ( chdir( cosign_dir ) < 0 ) {
	perror( cosign_dir );
	exit( 1 );
    }

    if ( replhost != NULL ) {
	if ( pusherhosts( replhost, port ) != 0 ) {
	    fprintf( stderr, "unhappy with lookup of %s\n", replhost );
	    exit( 1 );
	}
    }

    /*
     * Disassociate from controlling tty.
     */
    if ( !debug ) {
	int		i, dt;

	switch ( fork()) {
	case 0 :
	    if ( setsid() < 0 ) {
		perror( "setsid" );
		exit( 1 );
	    }
	    dt = getdtablesize();
	    for ( i = 0; i < dt; i++ ) {
		if ( i != s ) {			/* keep socket open */
		    (void)close( i );
		}
	    }
	    if (( i = open( "/", O_RDONLY, 0 )) == 0 ) {
		dup2( i, 1 );
		dup2( i, 2 );
	    }
	    break;
	case -1 :
	    perror( "fork" );
	    exit( 1 );
	default :
	    exit( 0 );
	}
    }

    /*
     * Start logging.
     */
#ifdef ultrix
    openlog( prog, LOG_NOWAIT|LOG_PID );
#else /* ultrix */
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_DAEMON );
#endif /* ultrix */

	if ( replhost != NULL ) {
    if ( pipe( fds ) < 0 ) {
	syslog( LOG_ERR, "pusher pipe: %m" );
	exit( 1 );
    }

    switch ( pusherpid = fork()) {
    case 0 :
	if ( close( fds[ 0 ] ) != 0 ) {
	    syslog( LOG_ERR, "pusher parent pipe: %m" );
	    exit( 1 );
	}
	pusherparent( fds[ 1 ] );
	exit( 0 );

    case -1 :
	syslog( LOG_ERR, "pusher fork: %m" );
	exit( 1 );

    default :
	if ( close( fds[ 1 ] ) != 0 ) {
	    syslog( LOG_ERR, "pusher main pipe: %m" );
	    exit( 1 );
	}
	if (( pushersn = snet_attach( fds[ 0 ], 1024 * 1024 ) ) == NULL ) {
	    syslog( LOG_ERR, "pusherfork: snet_attach failed\n" );
	    exit( 1 );
	}
	break;
    }
	}


    /* catch SIGHUP */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = hup;
    if ( sigaction( SIGHUP, &sa, &osahup ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    /* catch SIGCHLD */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = chld;
    if ( sigaction( SIGCHLD, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    syslog( LOG_INFO, "restart %s", cosign_version );



    /*
     * Begin accepting connections.
     */
    for (;;) {
	/* should select() so we can manage an event queue */

	sinlen = sizeof( struct sockaddr_in );
	if (( fd = accept( s, (struct sockaddr *)&sin, &sinlen )) < 0 ) {
	    if ( errno != EINTR ) {	/* other errors? */
		syslog( LOG_ERR, "accept: %m" );
	    }
	    continue;
	}

	/* start child */
	switch ( c = fork()) {
	case 0 :
	    syslog( LOG_INFO, "connect: %s", inet_ntoa( sin.sin_addr ));

	    (void)close( s );

	    /* reset CHLD and HUP */
	    if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
		syslog( LOG_ERR, "sigaction: %m" );
		exit( 1 );
	    }
	    if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
		syslog( LOG_ERR, "sigaction: %m" );
		exit( 1 );
	    }

	    exit( command( fd, pushersn ));

	case -1 :
	    close( fd );
	    syslog( LOG_ERR, "fork: %m" );
	    break;

	default :
	    close( fd );
	    break;
	}
    }
}

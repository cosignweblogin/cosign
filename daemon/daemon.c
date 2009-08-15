 /*
  * Copyright (c) 1999 Regents of The University of Michigan.
  * All Rights Reserved.  See LICENSE.
  */

#include "config.h"

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

#include <openssl/ssl.h>
#include <snet.h>

#include "logname.h"
#include "command.h"
#include "conf.h"
#include "rate.h"
#include "monster.h"
#include "pusher.h"


int		debug = 0;
int		backlog = 5;
int		pusherpid;
int		reconfig = 0;
int		child_signal = 0;

extern char	*cosign_version;
int		tlsopt = 0;
int		idle_out_time = 60 * 60 * 2;
int		grey_time = 60 * 30;
int		hashlen = 0;
int		strict_checks = 1;
char		*cosign_dir = _COSIGN_DIR;
char		*cosign_tickets = _COSIGN_TICKET_CACHE;
char		*cosign_conf = _COSIGN_CONF;
char		*cryptofile = _COSIGN_TLS_KEY;
char		*certfile = _COSIGN_TLS_CERT;
char		*cadir = _COSIGN_TLS_CADIR;
char		*replhost = NULL;
struct timeval	cosign_net_timeout = { 60 * 4, 0 };
unsigned short	cosign_port = 0;
SSL_CTX		*ctx = NULL;
struct sockaddr_in	cosign_sin;

void		hup( int );
void		chld( int );
int		main( int, char *av[] );

    static void
daemon_configure()
{
    char	 *val;

    if (( val = cosign_config_get( COSIGNDBKEY )) != NULL ) {
	cosign_dir = val;
    }

    if (( val = cosign_config_get( COSIGNDTICKKEY )) != NULL ) {
	cosign_tickets = val;
    }

    if (( val = cosign_config_get( COSIGNCADIRKEY )) != NULL ) {
	cadir = val;
    }

    if (( val = cosign_config_get( COSIGNCERTKEY )) != NULL ) {
	certfile = val;
    }

    if (( val = cosign_config_get( COSIGNKEYKEY )) != NULL ) {
	cryptofile = val;
    }

    if (( val = cosign_config_get( COSIGNTIMEOUTKEY )) != NULL ) {
	cosign_net_timeout.tv_sec = atoi( val );
	cosign_net_timeout.tv_usec = 0;
    }

    if (( val = cosign_config_get( COSIGNPORTKEY )) != NULL ) {
	cosign_port = htons( atoi( val ));
    }

    if (( val = cosign_config_get( COSIGNDBHASHLENKEY )) != NULL ) {
	hashlen = atoi( val );
    }

    if (( val = cosign_config_get( COSIGNSTRICTCHECKKEY )) != NULL ) {
	if ( strcasecmp( val, "off" ) == 0 ) {
	    strict_checks = 0;
	}
    }
}

    void
hup( int sig )
{
    reconfig++; 
    return;
}

    void
chld( int sig )
{
    child_signal++;
    return;
}

    int
main( int ac, char *av[] )
{
    struct sigaction	sa, osahup, osachld;
    struct sockaddr_in	sin;
    struct servent	*se;
    SNET		*pushersn = NULL;
    int			c, s, err = 0, fd;
    socklen_t		sinlen;
    int			dontrun = 0, fds[ 2 ];
    int			reuseaddr = 1, status;
    pid_t		pid;
    char		*prog;
    int                 facility = _COSIGN_LOG;
    int			level = LOG_INFO;
    int			fg = 0;
    extern int		optind;
    extern char		*optarg;

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }


#define	COSIGN_OPTS	"b:c:dD:F:fg:h:i:L:np:VXx:y:z:"
    while (( c = getopt( ac, av, COSIGN_OPTS )) != -1 ) {
	switch ( c ) {
	case 'c' :		/* config file */
	    cosign_conf = optarg;
	    break;

	default :
	    break;
	}
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	exit( 1 );
    }
    daemon_configure();

    /* reset optind to parse all other args */
    optind = 1;

    while (( c = getopt( ac, av, COSIGN_OPTS )) != -1 ) {
	switch ( c ) {
	case 'b' :		/* listen backlog */
	    backlog = atoi( optarg );
	    break;

	case 'c' :		/* already have conf file */
	    break;

	case 'd' :		/* debug */
	    debug = 1;
	    break;

	case 'D' :		/* directory to store cookies*/
	    cosign_dir = optarg;
	    break;

	case 'F' :              /* syslog facility */
	    if (( facility = syslogfacility( optarg )) == -1 ) {
		fprintf( stderr, "%s: %s: unknown syslog facility\n",
			prog, optarg );
		exit( 1 );
	    }
	    break;

	case 'f' :		/* run in foreground */
	    fg = 1;
	    break;

	case 'g' :		/* grey window for logouts/replication */
	    grey_time = atoi( optarg );
	    break;

	case 'h' :		/* host to replicate to*/
	    replhost = optarg;
	    break;

	case 'i' :		/* idle timeout in seconds */
	    idle_out_time  = atoi( optarg );
	    break;

	case 'L' :              /* syslog level */
	    if (( level = sysloglevel( optarg )) == -1 ) {
		fprintf( stderr, "%s: %s: unknown syslog level\n",
			prog, optarg );
		exit( 1 );
	    }
	    break;

	case 'n' :		/* don't run, just syntax check */
	    dontrun = 1;
	    break;

	case 'p' :		/* TCP port */
	    cosign_port = htons( atoi( optarg ));
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
	fprintf( stderr, "[ -c conf-file ] [ -D database-dir ] " );
	fprintf( stderr, "[ -F syslog-facility] " );
	fprintf( stderr, "[ -g greywindowinsecs ] [ -h replication_host] " );
	fprintf( stderr, "[ -i idletimeinsecs] [ -L syslog-level] " );
	fprintf( stderr, "[ -p port ] [ -x ca dir ] " );
	fprintf( stderr, "[ -y cert file] [ -z private key file ]\n" );
	exit( 1 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx ) != 0 ) {
	fprintf( stderr, "cosignd: ssl setup error.\n" );
	exit( 1 );
    }

    if ( dontrun ) {
	exit( 0 );
    }

    if ( cosign_port == 0 ) {
	if (( se = getservbyname( "cosign", "tcp" )) == NULL ) {
	    fprintf( stderr, "%s: can't find cosign service\n"
		    "%s: continuing...\n", prog, prog );
	    cosign_port = htons( 6663 );
	} else {
	    cosign_port = se->s_port;
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
    sin.sin_port = cosign_port;
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
	if ( pusherhosts( ) != 0 ) {
	    fprintf( stderr, "unhappy with lookup of %s\n", replhost );
	    exit( 1 );
	}
    }

    /*
     * Disassociate from controlling tty.
     */
    if ( !fg && !debug ) {
	int		i, dt;

	switch ( fork()) {
	case 0 :
	    if ( setsid() < 0 ) {
		perror( "setsid" );
		exit( 1 );
	    }
	    if (( fd = open( "/", O_RDONLY, 0 )) < 0 ) {
		perror( "open" );
		exit( 1 );
	    }
	    dt = getdtablesize();
	    for ( i = 0; i < dt; i++ ) {
		if (( i != s ) && ( i != fd )) {			
		    /* keep socket open */
		    (void)close( i );
		}
	    }
	    (void)dup2( fd, 0 );
	    (void)dup2( fd, 1 );
	    (void)dup2( fd, 2 );

	    (void)close( fd );
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
    openlog( prog, LOG_NDELAY|LOG_NOWAIT|LOG_PID, facility );
    setlogmask( LOG_UPTO( level ));

    syslog( LOG_INFO, "restart %s", cosign_version );

	if ( replhost != NULL ) {
    if ( pipe( fds ) < 0 ) {
	syslog( LOG_ERR, "pusher pipe: %m" );
	exit( 1 );
    }

    switch ( pusherpid = fork()) {
    case 0 :
	if ( close( fds[ 1 ] ) != 0 ) {
	    syslog( LOG_ERR, "pusher parent pipe: %m" );
	    exit( 1 );
	}
	pusherparent( fds[ 0 ] );
	exit( 0 );

    case -1 :
	syslog( LOG_ERR, "pusher fork: %m" );
	exit( 1 );

    default :
	if ( close( fds[ 0 ] ) != 0 ) {
	    syslog( LOG_ERR, "pusher main pipe: %m" );
	    exit( 1 );
	}
	if (( pushersn = snet_attach( fds[ 1 ], 1024 * 1024 ) ) == NULL ) {
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

    /*
     * Begin accepting connections.
     */
    for (;;) {
	/* ssl stuff here later, but for now this is HUP */
	if ( reconfig > 0 ) {
	    reconfig = 0;

syslog( LOG_DEBUG, "reload cosign_config %s", cosign_version );
	    if ( cosign_config( cosign_conf ) < 0 ) {
		syslog( LOG_ERR, "%s: re-read failed, continuing with"
			" old config", cosign_conf );
	    }

	    /* XXX need to reprocess command line args here */

syslog( LOG_DEBUG, "reload cosign_ssl %s", cosign_version );
	    if ( cosign_ssl( cryptofile, certfile, cadir, &ctx ) != 0 ) {
		syslog( LOG_ERR, "%s: ssl re-config failed, continuing with"
			" old ssl config", cosign_conf );
	    }

syslog( LOG_DEBUG, "reload kill %s", cosign_version );
	    if (pusherpid) {
		if ( kill( pusherpid, SIGHUP ) < 0 ) {
		    syslog( LOG_CRIT, "kill pusherpid: %m" );
		    exit( 1 );
	        }
	    }
	    syslog( LOG_INFO, "reload %s", cosign_version );
	}

	if ( child_signal > 0 ) {
	    child_signal = 0;
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
	}

	sinlen = sizeof( struct sockaddr_in );
	if (( fd = accept( s, (struct sockaddr *)&cosign_sin, &sinlen )) < 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR, "accept: %m" );
	    }
	    continue;
	}

	/* start child */
	switch ( c = fork()) {
	case 0 :
	    syslog( LOG_INFO, "connect: %s", inet_ntoa( cosign_sin.sin_addr ));

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

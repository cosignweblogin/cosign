#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "argcargv.h"
#include "monster.h"

extern char		*cosign_version;
extern char		*replhost;
extern SSL_CTX		*ctx;
static struct cl	*replhead;

static struct timeval   timeout = { 10 * 60, 0 };
static void     (*logger)( char * ) = NULL;

static void	pusherhup ( int );
static void	pusherchld ( int );
int		pusherparent( int );
int		pusher( int, struct cl * );
int		pusherhosts( char *, int );

    int
pusherhosts( char *name, int port)
{
    int			i;
    struct hostent	*he;
    struct cl		**tail = NULL, *new = NULL;

    if (( he = gethostbyname( name )) == NULL ) {
	return( 1 );
    }
    tail = &replhead;
    for ( i = 1; he->h_addr_list[ i ] != NULL; i++ ) {
	if (( new = ( struct cl * ) malloc( sizeof( struct cl ))) == NULL ) {
	    return( 1 );
	}

        memset( &new->cl_sin, 0, sizeof( struct sockaddr_in ));
        new->cl_sin.sin_family = AF_INET;
        new->cl_sin.sin_port = port;
        memcpy( &new->cl_sin.sin_addr.s_addr,
                he->h_addr_list[ i ], (unsigned int)he->h_length );
        new->cl_sn = NULL;
        new->cl_psn = NULL;
	new->cl_pid = 0;
        *tail = new;
        tail = &new->cl_next;
    }
    *tail = NULL;

    return( 0 );
}

    void
pusherhup( sig )
    int			sig;
{
    struct cl		*cur;

    /* hup all the children */
    for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	if ( cur->cl_pid < 0 ) {
	    continue;
	}
	if ( kill( cur->cl_pid, sig ) < 0 ) {
	    syslog( LOG_ERR, "pusherhup: %m" );
	}
    }

    syslog( LOG_INFO, "reload %s", cosign_version );

    return;
}

    void
pusherchld( sig )
    int			sig;
{
    int			pid, status;
    struct cl		*cur;
    extern int		errno;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	/* mark in the list that child has exited */
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( pid == cur->cl_pid ) {
syslog( LOG_DEBUG, "FOUND IT! %d", pid );
		cur->cl_pid = 0;
		if ( cur->cl_psn != NULL ) {
		    snet_close( cur->cl_psn );
		    cur->cl_psn = NULL;
		}
	    }
	}
	if ( WIFEXITED( status )) {
	    switch( WEXITSTATUS( status )) {
	    case 0:
		syslog( LOG_ERR, "CHILD %d exited", pid );
		break;

	    case 2:
		syslog( LOG_CRIT, "CHILD %d configuration error ", pid );
		exit( 1 );

	    default:
		syslog( LOG_ERR, "CHILD %d exited with %d", pid,
			WEXITSTATUS( status ));
		break;
	    }
	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "CHILD %d died on signal %d", pid,
		    WTERMSIG( status ));
	} else {
	    syslog( LOG_ERR, "CHILD %d died", pid );
	}
    }

    if ( pid < 0 && errno != ECHILD ) {
	syslog( LOG_ERR, "wait3: %m" );
	exit( 1 );
    }
    return;
}


    int
pusherparent( int ppipe )
{
    struct sigaction	sa, osahup, osachld;
    sigset_t 		signalset;
    SNET		*sn;
    char		*line;
    int			fds[ 2 ];
    int			max;
    fd_set		fdset;
    struct timeval	tv = { 0, 0 };
    struct cl		*cur, *yacur;

    /* catch SIGHUP */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = pusherhup;
    if ( sigaction( SIGHUP, &sa, &osahup ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }
    /* catch SIGCHLD */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = pusherchld;
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGCHLD, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }
    /* ignore SIGPIPE */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = SIG_IGN;
    if ( sigaction( SIGPIPE, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    sigemptyset( &signalset );
    sigaddset( &signalset, SIGCHLD );

    if (( sn = snet_attach( ppipe, 1024 * 1024 ) ) == NULL ) {
        syslog( LOG_ERR, "pusherparent: snet_attach failed\n" );
        return( -1 );
    }

    for ( ;; ) {
	if (( line = snet_getline( sn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherparent: snet_getline failed: %m\n" );
	    exit( 1 );
	}
syslog( LOG_INFO, "pusher line: %s", line );

	sigprocmask( SIG_BLOCK, &signalset, NULL );
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( cur->cl_pid != 0 ) {
		continue;
	    }
	    if ( pipe( fds ) < 0 ) {
		syslog( LOG_ERR, "pusherparent: %m" );
		exit( 1 );
	    }

	    switch ( cur->cl_pid = fork() ) {
	    case 0 :
syslog ( LOG_DEBUG, "pusher pid XXX for IP: %s", inet_ntoa(cur->cl_sin.sin_addr));
		if ( close( fds[ 0 ] ) != 0 ) {
		    syslog( LOG_ERR, "pusher parent pipe: %m" );
		    exit( 1 );
		}
		/* let's not leak fds if we can help it */
		close( ppipe );
		for ( yacur = replhead; yacur != NULL;
			yacur = yacur->cl_next ) {
		    if ( yacur != cur ) {
			if ( yacur->cl_psn != NULL ) {
			    snet_close( yacur->cl_psn );
			    yacur->cl_psn = NULL;
			}
		    }
		}
syslog( LOG_DEBUG, "XXX calling pusher()" );
		pusher( fds[ 1 ], cur );
		exit( 0 );

	    case -1 :
		syslog( LOG_ERR, "pusherparent fork: %m" );
		exit( 1 );
	    }

	    syslog( LOG_INFO, "started pusher %d", cur->cl_pid );

	    if ( close( fds[ 1 ] ) != 0 ) {
		syslog( LOG_ERR, "pusher main pipe: %m" );
		exit( 1 );
	    }

	    if (( cur->cl_psn = snet_attach( fds[ 0 ], 1024 * 1024 ))
		    == NULL ) {
		syslog( LOG_ERR, "pusherparent fork: snet_attach fail\n" );
		exit( 1 );
	    }
	}
	sigprocmask( SIG_UNBLOCK, &signalset, NULL );

	sigprocmask( SIG_BLOCK, &signalset, NULL );
	max = 0;
	FD_ZERO( &fdset );
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( cur->cl_pid > 0 ) {
		FD_SET( snet_fd( cur->cl_psn ), &fdset );
		if ( snet_fd( cur->cl_psn ) > max ) {
		    max = snet_fd( cur->cl_psn );
		}
	    }
	}
	sigprocmask( SIG_UNBLOCK, &signalset, NULL );

	if ( select( max + 1, NULL, &fdset, NULL, &tv ) < 0 ) {
	    continue;
	}

	sigprocmask( SIG_BLOCK, &signalset, NULL );
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( cur->cl_pid > 0 ) {
		if ( FD_ISSET( snet_fd( cur->cl_psn ), &fdset )) {
syslog( LOG_DEBUG, "writing to %d", cur->cl_pid );
		    snet_writef( cur->cl_psn, "%s\r\n", line );
		}
	    }
	}
	sigprocmask( SIG_UNBLOCK, &signalset, NULL );
    }

    return( 0 );
}

    int
pusher( int cpipe, struct cl *cur )
{
    SNET		*csn;
    char		*line, **av;
    int			rc, ac;
    struct timeval	tv;

    if (( csn = snet_attach( cpipe, 1024 * 1024 )) == NULL ) {
        syslog( LOG_ERR, "pusherchild: snet_attach failed" );
        return( -1 );
    }

    if (( rc = connect_sn( cur, ctx, replhost )) == -2 ) {
	syslog( LOG_ERR, "pusher: connect_sn permanent failure" );
	exit( 2 );
    } else if ( rc == -1 ) {
	syslog( LOG_ERR, "pusher: connect_sn transient failure" );
	exit( 1 );
    }

    for ( ;; ) {
	if (( line = snet_getline( csn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherchild: snet_getline failed" );
	    exit( 1 );
	}

syslog( LOG_INFO, "pusherchild: %s", line );

	if (( ac = argcargv( line, &av )) < 0 ) {
	    syslog( LOG_ERR, "argcargv: %m" );
	    break;
	}

	if ( ac <= 2 ) {
	    syslog( LOG_ERR, "pusherchild: not enuff args" );
	    break;
	}

	if (( strcasecmp( av[ 0 ], "login" )) == 0 ) {
	    if ( ac == 6 ) {
		/* kerberos stuff to boot */
	    } else {
		snet_writef( cur->cl_sn, "LOGIN %s %s %s %s\r\n",
			av[ 1 ], av [ 2 ], av [ 3 ], av [ 4 ] );
	    }
	} else if (( strcasecmp( av[ 0 ], "register" )) == 0 ) {
	    snet_writef( cur->cl_sn, "REGISTER %s %s %s\r\n",
			av[ 1 ], av[ 2 ], av [ 3 ] );

	} else if (( strcasecmp( av[ 0 ], "logout" )) == 0 ) {
	    snet_writef( cur->cl_sn, "LOGOUT %s %s %s\r\n",
			av[ 1 ], av[ 2 ], av [ 3 ] );
	} else {
	    syslog( LOG_ERR, "pusherchild: what's %s?", av[ 0 ]);
	}

	tv = timeout;
	if (( line = snet_getline_multi( cur->cl_sn, logger, &tv )) == NULL ) {
	    syslog( LOG_ERR, "pusherchild: %s\n", strerror( errno ));
	    if (( close_sn( cur )) != 0 ) {
		syslog( LOG_ERR, "pusherchld: close_sn failed\n" );
	    }
	    exit( 1 );
	}

	if ( *line != '2' ) {
	    syslog( LOG_ERR, "pusherchild: %s\n", line );
	    if (( close_sn( cur )) != 0 ) {
		syslog( LOG_ERR, "pusherchld: close_sn failed\n" );
	    }
	    exit( 1 );
	}

    }

    return( 0 );
}

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <netdb.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "monster.h"

extern char		*cosign_version;
extern char		*replhost;
extern SSL_CTX		*ctx;
static struct cl	*replhead;

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
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( pid == cur->cl_pid ) {
		cur->cl_pid = 0;
		if ( cur->cl_psn != NULL ) {
		    snet_close( cur->cl_psn );
		    cur->cl_psn = NULL;
		}
	    }
	}
	/* mark in the list that child has exited */
	if ( WIFEXITED( status )) {
	    switch( WEXITSTATUS( status )) {
	    case 0:
		syslog( LOG_ERR, "child %d exited", pid );
		break;

	    case 2:
		syslog( LOG_CRIT, "child %d configuration error ", pid );
		exit( 1 );

	    default:
		syslog( LOG_ERR, "child %d exited with %d", pid,
			WEXITSTATUS( status ));
		break;
	    }
	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "child %d died on signal %d", pid,
		    WTERMSIG( status ));
	} else {
	    syslog( LOG_ERR, "child %d died", pid );
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
    if ( sigaction( SIGCHLD, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    if (( sn = snet_attach( ppipe, 1024 * 1024 ) ) == NULL ) {
        syslog( LOG_ERR, "pusherparent: snet_attach failed\n" );
        return( -1 );
    }

    for ( ;; ) {
	if (( line = snet_getline( sn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherparent: snet_getline failed\n" );
	    exit( 1 );
	}
syslog( LOG_INFO, "pusher line: %s", line );

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
		if ( close( fds[ 0 ] ) != 0 ) {
		    syslog( LOG_ERR, "pusher parent pipe: %m" );
		    exit( 1 );
		}
		/* let's not leak fds if we can help it */
		close( ppipe );
		for ( yacur = replhead; yacur != NULL;
			yacur = yacur->cl_next ) {
		    if ( yacur != cur ) {
			snet_close( yacur->cl_psn );
		    }
		}
		pusher( fds[ 1 ], cur );
		exit( 0 );

	    case -1 :
		syslog( LOG_ERR, "pusherparent fork: %m" );
		exit( 1 );
	    }

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

	max = 0;
	FD_ZERO( &fdset );
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    FD_SET( snet_fd( cur->cl_psn ), &fdset );
	    if ( snet_fd( cur->cl_psn ) > max ) {
		max = snet_fd( cur->cl_psn );
	    }
	}

	if ( select( max + 1, NULL, &fdset, NULL, &tv ) < 0 ) {
	    continue;
	}

	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( FD_ISSET( snet_fd( cur->cl_psn ), &fdset )) {
		snet_writef( cur->cl_psn, "%s\r\n", line );
	    }
	}
    }

    return( 0 );
}

    int
pusher( int cpipe, struct cl *cur )
{
    SNET	*csn;
    char	*line;

    if (( csn = snet_attach( cpipe, 1024 * 1024 )) == NULL ) {
        syslog( LOG_ERR, "pusherchild: snet_attach failed" );
        return( -1 );
    }

    if ( connect_sn( cur, ctx, replhost ) != 0 ) {

    }
    for ( ;; ) {
	if (( line = snet_getline( csn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherchild: snet_getline failed" );
	    exit( 1 );
	}
    }

    return( 0 );
}

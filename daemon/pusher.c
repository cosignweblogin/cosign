#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "argcargv.h"
#include "monster.h"
#include "cparse.h"

extern char		*cosign_version;
extern char		*replhost;
extern unsigned int	port;
extern SSL_CTX		*ctx;
static struct cl	*replhead;

static struct timeval   timeout = { 10 * 60, 0 };
static void     (*logger)( char * ) = NULL;

static void	pusherhup ( int );
static void	pusherchld ( int );
int		pusherparent( int );
int		pusher( int, struct cl * );
int		pusherhosts( void );
void		pusherdaemon( struct cl * );

    void
pusherdaemon( struct cl *cur )
{
    struct timeval	tv;
    char		*line, hostname[ MAXHOSTNAMELEN ];

    if ( gethostname( hostname, sizeof( hostname )) < 0 ) {
	syslog( LOG_ERR, "pusherdaemon: %m" );
	return;
    }

    snet_writef( cur->cl_sn, "DAEMON %s\r\n", hostname );

    tv = timeout;
    if (( line = snet_getline_multi( cur->cl_sn, logger, &tv )) == NULL ) {
	syslog( LOG_ERR, "pusherdaemon: %m" );
	if (( close_sn( cur )) != 0 ) {
	    syslog( LOG_ERR, "pusherdaemon: close_sn: %m" );
	}
	exit( 1 );
    }

    if ( *line == '4' ) {
	if (( close_sn( cur )) != 0 ) {
	    syslog( LOG_ERR, "pusherdaemon: close_sn: %m" );
	}
	exit( 3 );
    } else if ( *line != '2' ) {
	syslog( LOG_ERR, "pusherdaemon: %s", line );
	if (( close_sn( cur )) != 0 ) {
	    syslog( LOG_ERR, "pusherdaemon: close_sn: %m" );
	}
	exit( 1 );
    }
    return;
}

    int
pusherhosts( void )
{
    int			i;
    struct hostent	*he;
    struct cl		**tail = NULL, *new = NULL;

    if (( he = gethostbyname( replhost )) == NULL ) {
	return( 1 );
    }
    tail = &replhead;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
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
pusherhup( int sig )
{
    struct cl		*cur;

    /* hup all the children */
    for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	if ( cur->cl_pid <= 0 ) {
	    continue;
	}

	if ( kill( cur->cl_pid, sig ) < 0 ) {
	    syslog( LOG_ERR, "pusherhup: %m" );
	}
    }

    if ( pusherhosts( ) != 0 ) {
	syslog( LOG_ERR, "unhappy with lookup of %s", replhost );
	exit( 1 );
    }

    syslog( LOG_INFO, "reload pusher %s", cosign_version );

    return;
}

    void
pusherchld( int sig )
{
    int			pid, status;
    struct cl		**cur, *temp;
    extern int		errno;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	/* mark in the list that child has exited */
	for ( cur = &replhead; *cur != NULL; cur = &(*cur)->cl_next ) {
	    if ( pid == (*cur)->cl_pid ) {
syslog( LOG_DEBUG, "FOUND IT! %d", pid );
		(*cur)->cl_pid = 0;
		if ( (*cur)->cl_psn != NULL ) {
		    snet_close( (*cur)->cl_psn );
		    (*cur)->cl_psn = NULL;
		}
		break;
	    }
	}
	if ( WIFEXITED( status )) {
	    switch( WEXITSTATUS( status )) {
	    case 0:
		syslog( LOG_ERR, "CHILD %d exited", pid );
		break;

	    case 2:
		syslog( LOG_CRIT, "CHILD %d configuration error", pid );
		exit( 1 );

	    case 3:
		syslog( LOG_ERR, "CHILD %d talking to itself", pid );
		/* remove from list */
		if ( *cur != NULL ) {
		    temp = *cur;
		    *cur = (*cur)->cl_next;
		    free( temp );
		}
		break;

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
    struct sigaction	sa;
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
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGHUP, &sa, NULL ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }
    /* catch SIGCHLD */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = pusherchld;
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGCHLD, &sa, NULL ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }
    /* ignore SIGPIPE */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = SIG_IGN;
    if ( sigaction( SIGPIPE, &sa, NULL ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    sigemptyset( &signalset );
    sigaddset( &signalset, SIGCHLD );

    if (( sn = snet_attach( ppipe, 1024 * 1024 ) ) == NULL ) {
        syslog( LOG_ERR, "pusherparent: snet_attach: %m" );
        return( -1 );
    }

    for ( ;; ) {
syslog( LOG_DEBUG, "PUSHERPARENT" );
syslog( LOG_DEBUG, "sleeping 5" );
	sleep( 5 );
	if (( line = snet_getline( sn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherparent: snet_getline: %m" );
	    exit( 1 );
	}

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
syslog ( LOG_DEBUG, "PUSHER: %s", inet_ntoa(cur->cl_sin.sin_addr));
		/* reset SIGCHLD & SIGHUP */
		memset( &sa, 0, sizeof( struct sigaction ));
		sa.sa_handler = SIG_DFL;
		if ( sigaction( SIGCHLD, &sa, NULL ) < 0 ) {
		    syslog( LOG_ERR, "sigaction: %m" );
		    exit( 1 );
		}

		memset( &sa, 0, sizeof( struct sigaction ));
		sa.sa_handler = SIG_DFL;
		if ( sigaction( SIGHUP, &sa, NULL ) < 0 ) {
		    syslog( LOG_ERR, "sigaction: %m" );
		    exit( 1 );
		}

		if ( close( fds[ 1 ] ) != 0 ) {
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
		pusher( fds[ 0 ], cur );
		exit( 0 );

	    case -1 :
		syslog( LOG_ERR, "pusherparent fork: %m" );
		exit( 1 );
	    }

	    if ( close( fds[ 0 ] ) != 0 ) {
		syslog( LOG_ERR, "pusher main pipe: %m" );
		exit( 1 );
	    }

	    if (( cur->cl_psn = snet_attach( fds[ 1 ], 1024 * 1024 ))
		    == NULL ) {
		syslog( LOG_ERR, "pusherparent fork: snet_attach: %m" );
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
syslog( LOG_DEBUG, "PUSHERPARENT: pid %d fd %d", cur->cl_pid, snet_fd( cur->cl_psn ));
		if ( snet_fd( cur->cl_psn ) > max ) {
		    max = snet_fd( cur->cl_psn );
		}
	    }
	}
	sigprocmask( SIG_UNBLOCK, &signalset, NULL );

tv.tv_sec = 1;
tv.tv_usec = 0;

	if ( select( max + 1, NULL, &fdset, NULL, &tv ) < 0 ) {
	    continue;
	}

syslog( LOG_DEBUG, "PUSHERPARENT: tv %d:%d", tv.tv_sec, tv.tv_usec );


	sigprocmask( SIG_BLOCK, &signalset, NULL );
	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( cur->cl_pid > 0 ) {
		if ( FD_ISSET( snet_fd( cur->cl_psn ), &fdset )) {
syslog( LOG_DEBUG, "PUSHERPARENT: writing to %d: %s", cur->cl_pid, line );
		    snet_writef( cur->cl_psn, "%s\r\n", line );
		} else {
syslog( LOG_DEBUG, "PUSHERPARENT: NOT writing to %d: %s", cur->cl_pid, line );
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
    unsigned char	buf[ 8192 ];
    char		*line, **av;
    int			rc, ac, krb = 0, fd = 0;
    ssize_t             rr, size = 0;
    struct timeval	tv;
    struct stat         st;
    struct cinfo	ci;

    if (( csn = snet_attach( cpipe, 1024 * 1024 )) == NULL ) {
        syslog( LOG_ERR, "pusherchild: snet_attach: %m" );
        return( -1 );
    }

    if (( rc = connect_sn( cur, ctx, replhost )) == -2 ) {
	syslog( LOG_ERR, "pusher: connect_sn permanent failure" );
	exit( 2 );
    } else if ( rc == -1 ) {
	syslog( LOG_ERR, "pusher: connect_sn transient failure" );
	exit( 1 );
    }
    
    pusherdaemon( cur );

	for ( ;; ) {
    krb = 0;
    if (( line = snet_getline( csn, NULL )) == NULL ) {
	syslog( LOG_ERR, "pusherchild: snet_getline: %m" );
	exit( 1 );
    }

syslog( LOG_DEBUG, "pusherchild: %s", line );

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
	    snet_writef( cur->cl_sn, "LOGIN %s %s %s %s kerberos\r\n",
		    av[ 1 ], av [ 2 ], av [ 3 ], av [ 4 ] );
	    krb = 1;
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
	exit( 1 );
    }

    tv = timeout;
    if (( line = snet_getline_multi( cur->cl_sn, logger, &tv )) == NULL ) {
	syslog( LOG_ERR, "pusherchld: %m" );
	exit( 1 );
    }

    if ( !krb ) {
syslog( LOG_DEBUG, "pusherchld: got back: %s", line );
	goto finish;
    }

    if ( *line != '3' ) {
        syslog( LOG_ERR, "pusherchld: not 3, got: %s", line );
        goto done;
    }

    if (( rc = read_cookie( av[ 1 ], &ci )) < 0 ) {
	syslog( LOG_ERR, "read_cookie error: %s", av[ 1 ] );
	continue;
    }

    if (( fd = open( ci.ci_krbtkt, O_RDONLY, 0 )) < 0 ) {
        syslog( LOG_ERR, "pusherchld: %m" );
        goto done;
    }

    if ( fstat( fd, &st) < 0 ) {
        syslog( LOG_ERR, "pusherchld: %m" );
        goto done;
    }

    size = st.st_size;
    if ( snet_writef( cur->cl_sn, "%d\r\n", (int)st.st_size ) < 0 ) {
        syslog( LOG_ERR, "login %s failed: %m", av[ 2 ] );
        goto done;
    }

    while (( rr = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = timeout;
        if ( snet_write( cur->cl_sn, buf, (int)rr, &tv ) != rr ) {
	    syslog( LOG_ERR, "login %s failed: %m", av[ 2 ] );
	    close( fd );
            goto done;
        }
        size -= rr;
    }

    close( fd );

    if ( rr < 0 ) {
        syslog( LOG_ERR, "pusherchld: %m" );
        goto done;
    }

    /* Check number of bytes sent to server */
    if ( size != 0 ) {
        syslog( LOG_ERR,
            "login %s failed: Wrong number of bytes sent", av[ 2 ] );
        goto done;
    }

    /* End transaction with server */
    if ( snet_writef( cur->cl_sn, ".\r\n" ) < 0 ) {
	syslog( LOG_ERR, "login %s failed: %m", av[ 2 ] );
        goto done;
    }

    tv = timeout;
    if (( line = snet_getline_multi( cur->cl_sn, logger, &tv )) == NULL ) {
        if ( snet_eof( cur->cl_sn )) {
            syslog( LOG_ERR, "pusherchld: connection closed" );
        } else {
            syslog( LOG_ERR, "pusherchld: login %s failed: %m\n", av[ 1 ] );
        }
    }

finish:
    if ( *line != '2' ) {
	syslog( LOG_ERR, "pusherchld: %s", line );
	if (( close_sn( cur )) != 0 ) {
	    syslog( LOG_ERR, "pusherchld: close_sn: %m" );
	}
	exit( 1 );
    }
	}

    return( 0 );

done:
    if (( close_sn( cur )) != 0 ) {
	syslog( LOG_ERR, "pusherchld: close_sn: %m" );
    }
    exit( 1 );
}

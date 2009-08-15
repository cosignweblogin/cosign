#include "config.h"

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
#include "rate.h"
#include "monster.h"
#include "cparse.h"
#include "mkcookie.h"

extern char		*cosign_version;
extern char		*replhost;
extern unsigned short	cosign_port;
extern SSL_CTX		*ctx;
extern struct timeval	cosign_net_timeout;
extern int		hashlen;

static struct connlist	*replhead = NULL;
static int		reconfig = 0;
static int		childsig = 0;

static void     (*logger)( char * ) = NULL;
static void	pusherhup( int );
static void	pusherchld( int );
static void	mkpushers( int );
static void	pusherdaemon( struct connlist * );
int		pusherparent( int );
int		pusher( int, struct connlist * );
int		pusherhosts( void );

    void
pusherdaemon( struct connlist *cur )
{
    struct timeval	tv;
    char		*line, hostname[ MAXHOSTNAMELEN ];

    if ( gethostname( hostname, sizeof( hostname )) < 0 ) {
	syslog( LOG_ERR, "pusherdaemon: %m" );
	return;
    }

    snet_writef( cur->cl_sn, "DAEMON %s\r\n", hostname );

    tv = cosign_net_timeout;
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
    struct connlist	**tail, *new, *cur, *next;

    if (( he = gethostbyname( replhost )) == NULL ) {
	return( 1 );
    }

    /*
     * Get rid of the old list, close descriptors, etc.
     */
    for ( cur = replhead; cur != NULL; cur = next ) {
	if ( cur->cl_psn != NULL ) {
	    snet_close( cur->cl_psn );
	}
	next = cur->cl_next;
	free( cur );
    }

    tail = &replhead;
    for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	if (( new = ( struct connlist * )
		malloc( sizeof( struct connlist ))) == NULL ) {
	    return( 1 );
	}

        memset( &new->cl_sin, 0, sizeof( struct sockaddr_in ));
        new->cl_sin.sin_family = AF_INET;
        new->cl_sin.sin_port = cosign_port;
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

    static void
pusherhup( int sig )
{
    reconfig++;
    return;
}

    static void
pusherchld( int sig )
{
     childsig++;
     return;
}

    void
mkpushers( int ppipe )
{
    struct connlist	*cur, *yacur;
    int			fds[ 2 ];
    struct sigaction	sa;

    for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	if ( cur->cl_pid != 0 ) {
	    continue;
	}
	if ( pipe( fds ) < 0 ) {
	    syslog( LOG_ERR, "mkpushers: %m" );
	    exit( 1 );
	}

	switch ( cur->cl_pid = fork() ) {
	case 0 :
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
	    cur->cl_pushpass.r_count = 0;
	    cur->cl_pushfail.r_count = 0;
	    pusher( fds[ 0 ], cur );
	    exit( 2 );

	case -1 :
	    syslog( LOG_ERR, "mkpushers fork: %m" );
	    exit( 1 );
	}

	if ( close( fds[ 0 ] ) != 0 ) {
	    syslog( LOG_ERR, "pusher main pipe: %m" );
	    exit( 1 );
	}

	if (( cur->cl_psn = snet_attach( fds[ 1 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "mkpushers fork: snet_attach: %m" );
	    exit( 1 );
	}
    }

    return;
}

    int
pusherparent( int ppipe )
{
    struct sigaction	sa;
    SNET		*sn;
    char		*line;
    int			max, status;
    pid_t		pid;
    fd_set		fdset;
    struct timeval	tvzero = { 0, 0 };
    struct connlist	*cur, **curp, *temp;
    double		rate;
    extern int		errno;

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

    if (( sn = snet_attach( ppipe, 1024 * 1024 ) ) == NULL ) {
        syslog( LOG_ERR, "pusherparent: snet_attach: %m" );
        return( -1 );
    }

    mkpushers( ppipe );

    for ( ;; ) {
	/* hup all the children */
	if ( reconfig ) {
	    reconfig = 0;
	    for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
		if ( cur->cl_pid <= 0 ) {
		    continue;
		}

syslog( LOG_DEBUG, "reload pusher kill %d %s", cur->cl_pid, cosign_version );
		if ( kill( cur->cl_pid, SIGHUP ) < 0 ) {
		    syslog( LOG_ERR, "pusherhup: %m" );
		}
	    }

syslog( LOG_DEBUG, "reload pusher pusherhosts %s", cosign_version );
	    if ( pusherhosts() != 0 ) {
		syslog( LOG_ERR, "unhappy with lookup of %s", replhost );
		exit( 1 );
	    }

	    syslog( LOG_INFO, "reload pusher %s", cosign_version );
	}

	if ( childsig ) {
	    childsig = 0;
	    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
		/* mark in the list that child has exited */
		for ( curp = &replhead; *curp != NULL;
			curp = &(*curp)->cl_next ) {
		    if ( pid == (*curp)->cl_pid ) {
			(*curp)->cl_pid = 0;
			if ( (*curp)->cl_psn != NULL ) {
			    snet_close( (*curp)->cl_psn );
			    (*curp)->cl_psn = NULL;
			}
			break;
		    }
		}
		if ( WIFEXITED( status )) {
		    switch( WEXITSTATUS( status )) {
		    case 0:
			syslog( LOG_ERR, "CHILD %d exited", pid );
			break;

		    case 1:
			syslog( LOG_ERR, "CHILD %d transient failure", pid );
			break;

		    case 2:
			syslog( LOG_CRIT, "CHILD %d configuration error", pid );
			exit( 1 );

		    case 3:
			syslog( LOG_ERR, "CHILD %d talking to itself", pid );
			/* remove from list */
			if ( *curp != NULL ) {
			    temp = *curp;
			    *curp = (*curp)->cl_next;
			    free( temp );
			}
			break;

		    default:
			syslog( LOG_ERR, "CHILD %d exited with %d", pid,
				WEXITSTATUS( status ));
			exit( 1 );
		    }
		} else if ( WIFSIGNALED( status )) {
		    syslog( LOG_ERR, "CHILD %d died on signal %d", pid,
			    WTERMSIG( status ));
		    if ( WTERMSIG( status ) != SIGHUP ) {
			exit( 1 );
		    }
		} else {
		    syslog( LOG_ERR, "CHILD %d died", pid );
		    exit( 1 );
		}
	    }

	    if ( pid < 0 && errno != ECHILD ) {
		syslog( LOG_ERR, "wait3: %m" );
		exit( 1 );
	    }
	}

	if (( line = snet_getline( sn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherparent: snet_getline: %m" );
	    exit( 1 );
	}

	mkpushers( ppipe );

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

	if ( select( max + 1, NULL, &fdset, NULL, &tvzero ) < 0 ) {
	    continue;
	}

	for ( cur = replhead; cur != NULL; cur = cur->cl_next ) {
	    if ( cur->cl_pid > 0 ) {
		if ( FD_ISSET( snet_fd( cur->cl_psn ), &fdset )) {
		    snet_writef( cur->cl_psn, "%s\r\n", line );
		    if (( rate = rate_tick( &cur->cl_pushpass )) != 0.0 ) {
			syslog( LOG_NOTICE, "STATS PUSH %s: PASS %.5f / sec",
				inet_ntoa( cur->cl_sin.sin_addr ), rate );
		    }
		} else {
		    if (( rate = rate_tick( &cur->cl_pushfail )) != 0.0 ) {
			syslog( LOG_NOTICE, "STATS PUSH %s: FAIL %.5f / sec",
				inet_ntoa( cur->cl_sin.sin_addr ), rate );
		    }
		}
	    }
	}
    }
}

    int
pusher( int cpipe, struct connlist *cur )
{
    SNET		*csn;
    char		buf[ 8192 ];
    char		*line, **av, path[ MAXPATHLEN ];
    int			rc, ac, krb = 0, fd = 0;
    ssize_t             rr, size = 0;
    struct timeval	tv;
    struct stat         st;
    struct cinfo	ci;

    if (( csn = snet_attach( cpipe, 1024 * 1024 )) == NULL ) {
        syslog( LOG_ERR, "pusher: snet_attach: %m" );
        exit( 1 );
    }

    if (( rc = connect_sn( cur, ctx, replhost, 0 )) < 0 ) {
	if ( rc == -2 ) {
	    syslog( LOG_ERR, "pusher: connect_sn permanent failure" );
	    exit( 2 );
	} else if ( rc == -1 ) {
	    syslog( LOG_ERR, "pusher: connect_sn transient failure" );
	    exit( 1 );
	}
	syslog( LOG_ERR, "pusher: connect_sn unknown failure" );
	exit( 2 );
    }
    
    pusherdaemon( cur );

	for ( ;; ) {
    krb = 0;
    if (( line = snet_getline( csn, NULL )) == NULL ) {
	syslog( LOG_ERR, "pusher: snet_getline: %m" );
	exit( 1 );
    }

    if (( ac = argcargv( line, &av )) < 0 ) {
	syslog( LOG_ERR, "argcargv: %m" );
	exit( 1 );
    }

    switch ( ac ) {
    case 6 :
	if (( strcasecmp( av[ 0 ], "login" )) != 0 ) {
	    syslog( LOG_ERR, "pusherchild: %s: bad command", av[ 0 ] );
	    exit( 1 );
	}
	snet_writef( cur->cl_sn, "LOGIN %s %s %s %s kerberos\r\n",
	    av[ 1 ], av [ 2 ], av [ 3 ], av [ 4 ] );
	krb = 1;
	break;

    case 5 :
	if (( strcasecmp( av[ 0 ], "login" )) != 0 ) {
	    syslog( LOG_ERR, "pusher: %s: bad command", av[ 0 ] );
	    exit( 1 );
	}
	snet_writef( cur->cl_sn, "LOGIN %s %s %s %s\r\n",
		av[ 1 ], av [ 2 ], av [ 3 ], av [ 4 ] );
	break;

    case 4 :
	if (( strcasecmp( av[ 0 ], "register" )) != 0 ) {
	    syslog( LOG_ERR, "pusher: %s: bad command", av[ 0 ] );
	    exit( 1 );
	}
	snet_writef( cur->cl_sn, "REGISTER %s %s %s\r\n",
		av[ 1 ], av[ 2 ], av [ 3 ] );
	break;

    case 3 :
	if (( strcasecmp( av[ 0 ], "logout" )) != 0 ) {
	    syslog( LOG_ERR, "pusher: %s: bad command", av[ 0 ] );
	    exit( 1 );
	}
	snet_writef( cur->cl_sn, "LOGOUT %s %s\r\n", av[ 1 ], av[ 2 ] );
	break;

    default :
	syslog( LOG_ERR, "pusher: wrong number of args" );
	exit( 1 );
    }

    tv = cosign_net_timeout;
    if (( line = snet_getline_multi( cur->cl_sn, logger, &tv )) == NULL ) {
	if ( !snet_eof( cur->cl_sn )) {
	    syslog( LOG_ERR, "pusher: getline: %m" );
	}
	exit( 1 );
    }

    /*
     * This is the branch of code where we'd expect a 3xx response, since
     * we're planning to send a kerberos ticket.  However, under conditions
     * of high load, the CGI may have timed out talking to a different
     * cosignd.  Since the CGI can also failover, there's some possibility
     * that the first cosignd actually got the data and at least partially
     * replicated it.  There's no way to tell (today) whether the other end
     * actually has kerberos tickets, tho.
     */
    if ( !krb || ( *line == '2' )) {
	goto done;
    }

    if ( *line != '3' ) {
        syslog( LOG_ERR, "pusher: not 3, got: %s", line );
        goto error;
    }

    if ( mkcookiepath( NULL, hashlen, av[ 1 ], path, sizeof( path )) < 0 ) {
	syslog( LOG_ERR, "pusher: mkcookiepath error: %s", av[ 1 ] );
        goto error;
    }

    if (( rc = read_cookie( path, &ci )) != 0 ) {
	syslog( LOG_ERR, "pusher: read_cookie error: %s", path );
	continue;
    }

    if (( fd = open( ci.ci_krbtkt, O_RDONLY, 0 )) < 0 ) {
        syslog( LOG_ERR, "pusher: open %s: %m", ci.ci_krbtkt );
        goto error;
    }

    if ( fstat( fd, &st) < 0 ) {
        syslog( LOG_ERR, "pusher: fstat: %m" );
        goto error;
    }

    size = st.st_size;
    if ( snet_writef( cur->cl_sn, "%d\r\n", (int)st.st_size ) < 0 ) {
        syslog( LOG_ERR, "login %s failed: %m", av[ 2 ] );
        goto error;
    }

    while (( rr = read( fd, buf, sizeof( buf ))) > 0 ) {
        tv = cosign_net_timeout;
        if ( snet_write( cur->cl_sn, buf, (int)rr, &tv ) != rr ) {
	    syslog( LOG_ERR, "login %s failed: %m", av[ 2 ] );
	    close( fd );
            goto error;
        }
        size -= rr;
    }

    close( fd );

    if ( rr < 0 ) {
        syslog( LOG_ERR, "pusher: rr: %m" );
        goto error;
    }

    /* Check number of bytes sent to server */
    if ( size != 0 ) {
        syslog( LOG_ERR,
            "login %s failed: Wrong number of bytes sent", av[ 2 ] );
        goto error;
    }

    /* End transaction with server */
    if ( snet_writef( cur->cl_sn, ".\r\n" ) < 0 ) {
	syslog( LOG_ERR, "login %s failed: %m", av[ 2 ] );
        goto error;
    }

    tv = cosign_net_timeout;
    if (( line = snet_getline_multi( cur->cl_sn, logger, &tv )) == NULL ) {
        if ( snet_eof( cur->cl_sn )) {
            syslog( LOG_ERR, "pusher: connection closed" );
        } else {
            syslog( LOG_ERR, "pusher: login %s failed: %m\n", av[ 1 ] );
        }
	exit( 1 );
    }

done:
    if (( *line != '2' ) && ( *line != '5' )) {
	syslog( LOG_ERR, "pusher: %s", line );
	if (( close_sn( cur )) != 0 ) {
	    syslog( LOG_ERR, "pusher: done: close_sn: %m" );
	}
	exit( 1 );
    }
	}

error:
    if (( close_sn( cur )) != 0 ) {
	syslog( LOG_ERR, "pusher: error: close_sn: %m" );
    }
    exit( 1 );
}

#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <netdb.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "monster.h"

extern char		*cosign_version;
static struct cl	*replhead;

static void	pusherhup ( int );
static void	pusherchld ( int );
int		pusherparent( int );
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
    syslog( LOG_INFO, "reload %s", cosign_version );
    /* hup all the children */

    return;
}

    void
pusherchld( sig )
    int			sig;
{
    int			pid, status;
    extern int		errno;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	/* mark in the list that child has exited */
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
    }

    if ( pid < 0 && errno != ECHILD ) {
	syslog( LOG_ERR, "wait3: %m" );
	exit( 1 );
    }
    return;
}


    int
pusherparent( int pipe )
{
    SNET	*sn;
    char	*line;

    if (( sn = snet_attach( pipe, 1024 * 1024 ) ) == NULL ) {
        syslog( LOG_ERR, "pusherparent: snet_attach failed\n" );
        return( -1 );
    }

    for ( ;; ) {
	if (( line = snet_getline( sn, NULL )) == NULL ) {
	    syslog( LOG_ERR, "pusherparent: snet_getline failed\n" );
	    exit( 1 );
	}
	/* loop thru hosts */
	    /* check for pid? */
	    /* if no pid, fork and crap i don't get */
	/* select */
	/* zeroed out tv for not wait */
	/* for any fds that are set we write the line */

	syslog( LOG_INFO, "pusher line: %s", line );

    }

    return( 0 );

}

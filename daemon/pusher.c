#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>

extern char	*cosign_version;

void	 pusherhup ( int );
void	 pusherchld ( int );
int	 pusherparent( int );


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

return( 0 );

}

/*
 * Copyright (c) 2006 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <openssl/ssl.h>

#include <snet.h>
#include <cgi.h>

#include "conf.h"
#include "factor.h"

    int
execfactor( struct factorlist *fl, struct cgi_list cl[], char **msg )
{
    int			fd0[ 2 ], fd1[ 2 ], i, status;
    pid_t		pid;
    SNET		*sn_r, *sn_w;
    struct timeval	tv;
    char		**ff, *line;
    static char		prev[ 1024 ];

    *msg = NULL;

    if ( pipe( fd0 ) < 0 || pipe( fd1 ) < 0 ) {
	perror( "pipe" );
	exit( 1 );
    }

    switch ( pid = fork()) {
    case -1 :
	perror( "fork" );
	if ( close( fd0[ 0 ] ) < 0 || close( fd0[ 1 ] ) < 0 ||
		close( fd1[ 0 ] ) < 0 || close( fd1[ 1 ] ) < 0 ) {
	    perror( "close" );
	}
	exit( 1 );

    case 0 :
	if ( dup2( fd0[ 0 ], 0 ) < 0 || dup2( fd1[ 1 ], 1 ) < 0 ) {
	    perror( "dup2" );
	    exit( 1 );
	}
	if ( close( fd0[ 0 ] ) < 0 || close( fd0[ 1 ] ) < 0 ||
		close( fd1[ 0 ] ) < 0 || close( fd1[ 1 ] ) < 0 ) {
	    perror( "close" );
	    exit( 1 );
	}
	execl( fl->fl_path, fl->fl_path, NULL );
	perror( fl->fl_path );
	exit( 1 );

    default :
	break;
    }

    if ( close( fd0[ 0 ] ) < 0 || close( fd1[ 1 ] ) < 0 ) {
	perror( "close" );
	exit( 1 );
    }
    if (( sn_w = snet_attach( fd0[ 1 ], 1024 * 1024 )) == NULL ||
	    ( sn_r = snet_attach( fd1[ 0 ], 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    for ( ff = fl->fl_formfield; *ff != NULL; ff++ ) {
	for ( i = 0; cl[ i ].cl_key != NULL; i++ ) {
	    if ( strcmp( *ff, cl[ i ].cl_key ) == 0 ) {
		if ( snet_writef( sn_w, "%s\n", cl[ i ].cl_data ) < 0 ) {
		    perror( "snet_writef" );
		    exit( 1 );
		}
	    }
	}
    }
    if ( snet_close( sn_w ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    tv.tv_sec = 10;
    tv.tv_usec = 0;
    while (( line = snet_getline( sn_r, &tv )) != NULL ) {
	strncpy( prev, line, sizeof( prev ));
	prev[ sizeof( prev ) - 1 ] = '\0';
    }
    if ( errno == ETIMEDOUT ) {
	kill( pid, SIGKILL );
    }

    if ( snet_close( sn_r ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    if ( waitpid( pid, &status, 0 ) == -1 ) {
	perror( "waitpid" );
	exit( 1 );
    }

    if ( WIFEXITED( status )) {
	switch ( WEXITSTATUS( status )) {
	case 0 :
	    *msg = prev;
	    return( 0 );
	case 1 :
	    *msg = prev;
	    return( 1 );
	case 2 :
	    *msg = prev;
	    return( 2 );
	default :
	    fprintf( stderr, "factor %s exited with %d\n", fl->fl_path,
		    WEXITSTATUS( status ));
	    exit( 1 );
	}
    } else if ( WIFSIGNALED( status )) {
	fprintf( stderr, "factor %s killed with %d\n", fl->fl_path,
		WTERMSIG( status ));
	*msg = "Factor killed";
	return( 1 );
    } else {
	fprintf( stderr, "factor %s died\n", fl->fl_path );
	exit( 1 );
    }
}

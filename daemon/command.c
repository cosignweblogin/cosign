/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <snet.h>

#include "command.h"

extern char	*version;

struct command {
    char	*c_name;
    int		(*c_func) ___P(( SNET *, int, char *[] ));
};

static int	f_noop ___P(( SNET *, int, char *[] ));
static int	f_quit ___P(( SNET *, int, char *[] ));
static int	f_help ___P(( SNET *, int, char *[] ));


    int
f_quit( snet, ac, av )
    SNET			*snet;
    int				ac;
    char			*av[];
{
    snet_writef( snet, "%d Service closing transmission channel\r\n", 221 );
    exit( 0 );
}


    int
f_noop( snet, ac, av )
    SNET			*snet;
    int				ac;
    char			*av[];
{
    snet_writef( snet, "%d cosign v%s\r\n", 250, version );
    return( 0 );
}

    int
f_help( sn, ac, av )
    SNET        *sn;
    int         ac;
    char        *av[];
{
    snet_writef( sn, "%d Vaild commands are HELP, NOOP, and QUIT\r\n", 203 );
    return( 0 );
}



struct command	commands[] = {
    { "NOOP",		f_noop },
    { "QUIT",		f_quit },
    { "HELP",		f_help },
};
int		ncommands = sizeof( commands ) / sizeof( commands[ 0 ] );

    int
command( fd )
    int			fd;
{
    SNET				*snet;
    int					ac, i;
    char				**av, *line;
    struct timeval			tv;

    srandom( (unsigned)getpid());

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	/* We *could* use write(2) to report an error before we exit here */
	exit( 1 );
    }

    snet_writef( snet, "%d COokie SIGNer ready\r\n", 220 );

    tv.tv_sec = 60 * 10;	/* 10 minutes, should get this from config */
    tv.tv_usec = 0;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = 60 * 10;
	tv.tv_usec = 0;

	if (( ac = argcargv( line, &av )) < 0 ) {
	    syslog( LOG_ERR, "argcargv: %m" );
	    break;
	}

	if ( ac == 0 ) {
	    snet_writef( snet, "%d Command unrecognized\r\n", 501 );
	    continue;
	}

	for ( i = 0; i < ncommands; i++ ) {
	    if ( strcasecmp( av[ 0 ], commands[ i ].c_name ) == 0 ) {
		break;
	    }
	}
	if ( i >= ncommands ) {
	    snet_writef( snet, "%d Command %s unregcognized\r\n",
		    500, av[ 0 ] );
	    continue;
	}

	if ( (*(commands[ i ].c_func))( snet, ac, av ) < 0 ) {
	    break;
	}
    }

    snet_writef( snet,
	    "421 Service not available, closing transmission channel\r\n" );

    if ( line == NULL ) {
	syslog( LOG_ERR, "snet_getline: %m" );
    }

    exit( 1 );

}

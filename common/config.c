/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include <snet.h>

#include "wildcard.h"
#include "config.h"
#include "argcargv.h"

struct chosts	*authlist = NULL;

static void chosts_free();

    struct chosts *
chosts_find( char *hostname )
{
    struct chosts	*cur = NULL;

    for ( cur = authlist; cur != NULL; cur = cur->ch_next ) {
	if ( wildcard( cur->ch_hostname, hostname )) {
	    break;
	}
    }
    return( cur );
}

    static void
chosts_free()
{
    struct chosts 	*cur, *next;

    cur = authlist;
    while ( cur != NULL ) {
	free( cur->ch_hostname );
	next = cur->ch_next;
	free( cur );
	cur = next;
    }
    authlist = NULL;
    return;
}

/*
 * File format is
 *	keyword hostname [krbtgt(0/1)]
 */
    int
chosts_read( char *path )
{
    SNET		*sn;
    struct chosts	**cur, *new;
    char		**av, *line;
    int			ac;
    int			linenum = 0;

    if ( authlist != NULL ) {
	chosts_free( );
    }

    if (( sn = snet_open( path, O_RDONLY, 0, 0 )) == NULL ) {
	perror( path );
	return( -1 );
    }

    cur = &authlist;

    while (( line = snet_getline( sn, NULL )) != NULL ) {
	linenum++;
	if (( ac = argcargv( line, &av )) < 0 ) {
	    perror( "argcargv" );
	    return( -1 );
	}
	if ( ac == 0 || *av[ 0 ] == '#' ) {
	    continue;
	}

	if ( ac != 2 && ac != 3 ) {
	    fprintf( stderr, "%s: line %d, wrong number of args\n",
		    path, linenum );
	    return( -1 );
	}

	if (( new = (struct chosts *)malloc( sizeof( struct chosts )))
		== NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}

	if ( strcmp( av[ 0 ], "cgi" ) == 0 ) {
	    new->ch_key = CGI;
	} else if ( strcmp( av[ 0 ], "service" ) == 0 ) {
	    new->ch_key = SERVICE;
	} else {
	    new->ch_key = NOTAUTH;
	}

	new->ch_hostname = strdup( av[ 1 ] );

	if (( ac == 3 ) && ( new->ch_key == SERVICE )) {
	    new->ch_tkt = atoi( av[ 2 ] );
	} else {
	    new->ch_tkt = 0;
	}

	*cur = new;
	cur = &new->ch_next;
    }

    *cur = NULL;

    /* check for net_error */
    return( snet_close( sn ));
}

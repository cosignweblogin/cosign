/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#include <snet.h>

#include "sparse.h"
#include "cosign.h"

void                    (*logger)( char * ) = NULL;
struct timeval          timeout = { 10 * 60, 0 };
struct connlist         *conn_head = NULL;

    int
copy_connections( struct sinlist *s_cur )
{
    struct connlist **cur = NULL, *new = NULL;
    int	c = -1;

    if ( s_cur->s_copied ) {
	fprintf( stderr, "sl already copied\n" );
	choose_conn();
	return( 0 );
    }

    for ( ; s_cur != NULL; s_cur = s_cur->s_next ) {
	for ( cur = &conn_head; *cur != NULL; cur = &(*cur)->conn_next ) {
	    if (( c = memcmp( &s_cur->s_sin, &(*cur)->conn_sin,
		    sizeof( struct sockaddr_in ))) == 0 ) {
		break;
	    }
	}
	if ( c == 0 ) {
	    s_cur->s_copied = 1;
	    continue;
	}
	if (( new = ( struct connlist * ) malloc( sizeof( struct connlist )))
		== NULL ) {
	    exit( 1 );
	}
	new->conn_sn = NULL;
	new->conn_flag |= CONN_UNUSED;
	memcpy( &new->conn_sin, &s_cur->s_sin, sizeof( struct sockaddr_in ));
	s_cur->s_copied = 1;
	new->conn_next = *cur;
	*cur = new;
    }
    choose_conn();

    return( 0 );
}

    int
choose_conn( )
{
    struct connlist *cur = NULL;

    for ( cur = conn_head; cur != NULL; cur = cur->conn_next ) {
	if ( cur->conn_flag & CONN_OPEN ) {
	    fprintf( stderr, "we theoretically have a conn open.\n" );
	    return( 0 );
	}
	if ( cur->conn_flag & CONN_PROB ) {
	    fprintf( stderr, "we theoretically have a conn problem.\n" );
	} else {
	    fprintf( stderr, "opening conn...\n" );
	    if ( connect_sn( cur ) != 0 ) {
		continue;
	    }
	    break;
	}
    }

    if ( cur == NULL ) {
	return( -1 );
    }

    /* this needs work :) XXX */
    if ( cur->conn_next == NULL ) {
	return( 0 );
    }

    cur = conn_head->conn_next;
    conn_head->conn_next = cur->conn_next;
    cur->conn_next = conn_head;
    conn_head = cur;

    /* we've gotten here cos there's either no conns, one 
     * still works or we have a new one. in the last case 
     * we need to re-order the list.
     */
    return( 0 );
}


    int
connect_sn( struct connlist *cl )
{
    int			i, s;
    char		*line;
    struct timeval      tv;

    if ( ( s = socket( PF_INET, SOCK_STREAM, NULL ) ) < 0 ) {
	    cl->conn_flag |= CONN_PROB;
	    return( 1 );
    }

    if ( connect( s, ( struct sockaddr *)&cl->conn_sin,
	    sizeof( struct sockaddr_in ) ) != 0 ) {
	perror( "connect" );
	(void)close( s );
	cl->conn_flag |= CONN_PROB;
	return( 1 );
    }

    if ( ( cl->conn_sn = snet_attach( s, 1024 * 1024 ) ) == NULL ) {
	/* log something */
	(void)close( s );
	cl->conn_flag |= CONN_PROB;
	return( 1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( cl->conn_sn, logger, &tv) ) == NULL ) {
	    /* log something */
	if ( snet_close( cl->conn_sn ) != 0 ) {
	    /* log something */
	}
	cl->conn_flag |= CONN_PROB;
	return( 1 );
    }
fprintf( stderr, "%s\n", line);
    if ( *line !='2' ) {
	fprintf( stderr, "%s\n", line);
	if ( snet_close( cl->conn_sn ) != 0 ) {
	    /* log something */
	}
	cl->conn_flag |= CONN_PROB;
	return( 1 );
    }

    cl->conn_flag |= CONN_OPEN;
    return( 0 );
}
    int
teardown_conn( )
{
    struct connlist *cur = NULL;

    for ( cur = conn_head; cur != NULL; cur = cur->conn_next ) {
	if ( cur->conn_sn != NULL  ) {
	    if ( close_sn( cur->conn_sn ) != 0 ) {
	    /* log something */
	    }
	}
    }
    return( 0 );
}

    int
close_sn( SNET *sn )
{
    char		*line;
    struct timeval      tv;

    /* Close network connection */
    if ( snet_writef( sn, "QUIT\r\n" ) == NULL ) {
	/* log something */
	return( 1 );
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( sn, logger, &tv ) ) == NULL ) {
	/* log something */
	return( 1 );
    }
    if ( *line != '2' ) {
	/* log something */
    }
    if ( snet_close( sn ) != 0 ) {
	/* log something */
	return( 1 );
    }
    return( 0 );
}

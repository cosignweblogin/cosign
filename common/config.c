/*
 * Copyright (c) 2004 Regents of The University of Michigan.
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

struct authlist		*authlist = NULL;
struct cosigncfg 	*cfg = NULL;

static void authlist_free();


    static void
free_config()
{
    struct cosigncfg *ptr;

    while( cfg ) {
	free( cfg->cc_key );
	free( cfg->cc_value );
	ptr = cfg->cc_next;
	free( cfg );
	cfg = ptr;
    }
    cfg = NULL;
}

    char **
cosign_config_get_all( char *key, int *nVals )
{
    struct cosigncfg *ptr;

    for ( ptr = cfg; ptr; ptr = ptr->cc_next ) {
	if (( strcmp( ptr->cc_key, key ) == 0 )  && ptr->cc_numval ) {
	    *nVals = ptr->cc_numval;
	    return( ptr->cc_value );
	}
    }

    *nVals = 0;
    return( NULL );
}

    char *
cosign_config_get( char *key )
{
    struct cosigncfg *ptr;

    for ( ptr = cfg; ptr; ptr = ptr->cc_next ) {
	if (( strcmp( ptr->cc_key, key ) == 0 ) && ptr->cc_numval ) {
	    return( ptr->cc_value[ 0 ] );
	}
    }
    return( NULL );
}

    struct authlist *
authlist_find( char *hostname )
{
    struct authlist	*cur = NULL;

    for ( cur = authlist; cur != NULL; cur = cur->al_next ) {
	/* 0 makes this match case insensitive */
	if ( wildcard( cur->al_hostname, hostname, 0 )) {
	    break;
	}
    }
    return( cur );
}

    static void
authlist_free()
{
    struct authlist 	*cur, *next;
    struct proxies	*pcur, *pnext;

    for ( cur = authlist; cur != NULL; cur = next ) {
	free( cur->al_hostname );
	for ( pcur = cur->al_proxies; pcur != NULL; pcur = pnext ) {
	    free( pcur->pr_hostname );
	    free( pcur->pr_cookie );
	    pnext = pcur;
	    free( pcur );
	}
	next = cur->al_next;
	free( cur );
    }
    authlist = NULL;
    return;
}

/*
 * File format is
 *	host cookie
 */
    static int
proxy_read( struct authlist *authlist, char *path )
{
    SNET		*sn;
    struct proxies	*new;
    char		**av, *line;
    int			ac;
    int			linenum = 0;

    if (( sn = snet_open( path, O_RDONLY, 0, 0 )) == NULL ) {
	perror( path );
	return( -1 );
    }

    while (( line = snet_getline( sn, NULL )) != NULL ) {
	linenum++;
	if (( ac = argcargv( line, &av )) < 0 ) {
	    perror( "argcargv" );
	    return( -1 );
	}
	if ( ac == 0 || *av[ 0 ] == '#' ) {
	    continue;
	}

	if ( ac != 2 ) {
	    fprintf( stderr, "%s: line %d, wrong number of args\n",
		    path, linenum );
	    return( -1 );
	}

	if (( new = (struct proxies *)malloc( sizeof( struct proxies )))
		== NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}
	if (( new->pr_hostname = strdup( av[ 0 ] )) == NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}
	if (( new->pr_cookie = strdup( av[ 1 ] )) == NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}

	new->pr_next = authlist->al_proxies;
	authlist->al_proxies = new;
    }

    /* check for net_error */
    return( snet_close( sn ));
}

    static int
read_config( char *path )
{
    SNET		*sn;
    char		**av, *line;
    int			ac, i;
    int			linenum = 0;
    struct cosigncfg	*cc_new, **cc_cur;
    struct authlist 	*al_new, **al_cur;

    if (( sn = snet_open( path, O_RDONLY, 0, 0 )) == NULL ) {
	perror( path );
	return( -1 );
    }

    while (( line = snet_getline( sn, NULL )) != NULL ) {
	linenum++;
	if (( ac = argcargv( line, &av )) < 0 ) {
	    perror( "argcargv" );
	    return( -1 );
	}
	if ( ac == 0 || *av[ 0 ] == '#' ) {
	    continue;
	}
	
	if ( strcmp( av[ 0 ], "set" ) == 0 ) {
	    if ( ac < 3 ) {
		fprintf( stderr, "%s: line %d, "
			"wrong number of args for config keyword\n",
			path, linenum );
		return( -1 );
	    }
	    if (( cc_new = malloc( sizeof( struct cosigncfg ))) == NULL ) {
		perror( "malloc for config line" );
		return( -1 );
	    }

	    cc_new->cc_key = strdup( av[ 1 ] );
	    cc_new->cc_numval = ac - 2;
	    cc_new->cc_next = NULL;

	    if (( cc_new->cc_value =
		    (char **)calloc( cc_new->cc_numval, sizeof( char * )))
		    == NULL ) {
		perror( "malloc for config line" );
		return( -1 );
	    }

	    for ( i = 0; i < cc_new->cc_numval; i++ ) {
		cc_new->cc_value[ i ] = strdup( av[ i + 2 ] );

	    }
	    for ( cc_cur = &cfg; (*cc_cur) != NULL;
		    cc_cur = &(*cc_cur)->cc_next )
		;

	    cc_new->cc_next = *cc_cur;
	    *cc_cur = cc_new;

	} else if ( strcmp( av[ 0 ],"include" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d, "
			"wrong number args to include keyword\n",
			path, linenum );
		continue;
	    }
	    if ( read_config( av[ 1 ] )) {
		fprintf( stderr,"%s line %d\n", path, linenum );
		return( -1 );
	    }
	} else {
	    if ( strcmp( av[ 0 ], "cgi" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "line %d: keyword cgi takes 2 args\n",
			    linenum );
		    return( -1 );
		}

		if (( al_new =
			(struct authlist *)malloc( sizeof( struct authlist )))
			== NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
		al_new->al_next = NULL;

		al_new->al_key = CGI;
		al_new->al_hostname = strdup( av[ 1 ] );
		al_new->al_flag = 0;
		al_new->al_proxies = NULL;

	    } else if ( strcmp( av[ 0 ], "service" ) == 0 ) {
		if (( ac != 3 ) && ( ac != 4 )) {
		    fprintf( stderr,
			"line %d: keyword service takes 3 or 4 args\n",
			linenum );
		    return( -1 );
		}
		if (( al_new =
			(struct authlist *)malloc( sizeof( struct authlist )))
			== NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
		al_new->al_next = NULL;
		al_new->al_key = SERVICE;
		al_new->al_hostname = strdup( av[ 1 ] );
		al_new->al_flag = 0;

		if ( strchr( av[ 2 ], 'T' ) != 0 ) {
		    al_new->al_flag |= AL_TICKET;
		} 

		if ( strchr( av[ 2 ], 'P' ) != 0 ) {
		    if ( ac != 4 ) {
			fprintf( stderr, "%s: line %d: proxy\n",
				path, linenum );
			return( -1 );
		    }
		    if ( proxy_read( al_new, av[ 3 ] ) < 0 ) {
			fprintf( stderr, "proxy read failed line %d\n",
			    linenum );
			return( -1 ); 
		    }
		    al_new->al_flag |= AL_PROXY;
		}

	    } else if ( strcmp( av[ 0 ], "notauth" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "line %d: keyword notauth takes 2 args\n",
			    linenum );
		    return( -1 );
		}
		if (( al_new =
			(struct authlist *)malloc( sizeof( struct authlist )))
			== NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
		al_new->al_next = NULL;
		al_new->al_key = NOTAUTH;
		al_new->al_hostname = strdup( av[ 1 ] );
		al_new->al_flag = 0;

	    } else {
		fprintf( stderr, "invalid keyword line %d: %s\n",
			linenum, av[ 0 ] );
		return( -1 );
	    }

	    for ( al_cur = &authlist; (*al_cur) != NULL;
		    al_cur = &(*al_cur)->al_next )
		;

	    al_new->al_next = *al_cur;
	    *al_cur = al_new;

	}
    }

    return( snet_close( sn ));
}


/*
 * File format is
 *	cgi hostname
 *	service hostname 0
 *	service hostname T
 *	service hostname P path
 *	service hostname TP path
 *	notauth hostname
 *	set key value
 *	include configfilepath
 */
    int
cosign_config( char *path )
{
    if ( authlist != NULL ) {
	authlist_free( );
    }

    if ( cfg != NULL ) {
	free_config();
    }

    return read_config( path );
}

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

struct chosts		*authlist = NULL;
struct cosigncfg 	*cfg = NULL;

static void chosts_free();
struct chosts *chosts_read( int ac, char **av, char *path, int linenum );

    static void
addchost( struct chosts *ch )
{
    struct chosts *ptr = authlist;

    if ( authlist) {
	for ( ; ptr->ch_next; ptr = ptr->ch_next ) {
	    ptr->ch_next = ch;
	}
    } else {
	authlist = ch;
    }
}

    static void
addConfig( struct cosigncfg *cfgin )
{
    struct cosigncfg 	*ptr = cfg;

    if ( cfg ) {
	for ( ; ptr->cc_next; ptr = ptr->cc_next ) {
	    ptr->cc_next = cfgin;
	}
    } else {
	cfg = cfgin;
    }
}

    static void
freeConfig()
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
getAllConfigValues( char *key, int *nVals )
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
getConfigValue( char *key )
{
    struct cosigncfg *ptr;

    for ( ptr = cfg; ptr; ptr = ptr->cc_next ) {
	if (( strcmp( ptr->cc_key, key ) == 0 ) && ptr->cc_numval ) {
	    return( ptr->cc_value[ 0 ] );
	}
    }
    return( NULL );
}

    struct chosts *
chosts_find( char *hostname )
{
    struct chosts	*cur = NULL;

    for ( cur = authlist; cur != NULL; cur = cur->ch_next ) {
	/* 0 makes this match case insensitive */
	if ( wildcard( cur->ch_hostname, hostname, 0 )) {
	    break;
	}
    }
    return( cur );
}

    static void
chosts_free()
{
    struct chosts 	*cur, *next;
    struct proxies	*pcur, *pnext;

    for ( cur = authlist; cur != NULL; cur = next ) {
	free( cur->ch_hostname );
	for ( pcur = cur->ch_proxies; pcur != NULL; pcur = pnext ) {
	    free( pcur->pr_hostname );
	    free( pcur->pr_cookie );
	    pnext = pcur;
	    free( pcur );
	}
	next = cur->ch_next;
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
proxy_read( struct chosts *chost,char *path )
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

	new->pr_next = chost->ch_proxies;
	chost->ch_proxies = new;
    }

    /* check for net_error */
    return( snet_close( sn ));
}

    struct chosts *
chosts_read( int ac, char **av, char *path, int linenum )
{
    struct chosts *new = NULL;

    if (( new = (struct chosts *)malloc( sizeof( struct chosts )))
	    == NULL ) {
	perror( "malloc" );
	return NULL;
    }
    new->ch_next=NULL;

    if ( strcmp( av[ 0 ], "cgi" ) == 0 ) {
	new->ch_key = CGI;
    } else if ( strcmp( av[ 0 ], "service" ) == 0 ) {
	new->ch_key = SERVICE;
    } else {
	new->ch_key = NOTAUTH;
    }

    new->ch_hostname = strdup( av[ 1 ] );
    new->ch_flag = 0;
    new->ch_proxies = NULL;

    if (( ac >= 3 ) && (( new->ch_key == SERVICE || new->ch_key == CGI ))) {
	if ( strchr( av[ 2 ], 'T' ) != 0 ) {
	    new->ch_flag |= CH_TICKET;
	}
	if ( strchr( av[ 2 ], 'P' ) != 0 ) {
	    if ( ac != 4 ) {
		fprintf( stderr, "%s: line %d, wrong number of args\n",
			path, linenum );
		return NULL;
	    }
	    if ( proxy_read( new, av[ 3 ] ) < 0 ) {
		return NULL;
	    }
	    new->ch_flag |= CH_PROXY;
	}
    }
    return( new );
}

/*
 * parse a config line which is of form:
 *	config key value
 *
 * return the config structure or null on failure
 */
    static struct cosigncfg *
processConfigLine( int ac, char **av )
{
    int 		i;
    struct cosigncfg 	*new = NULL;

    if (( new = malloc( sizeof( struct cosigncfg ))) == NULL ) {
	perror( "malloc for config line" );
	return( NULL );
    }

    new->cc_key = strdup( av[ 1 ] );
    new->cc_numval = ac - 2;

    if (( new->cc_value = (char **)calloc( new->cc_numval, sizeof( char * )))
	    == NULL ) {
	perror( "malloc for config line" );
	return( NULL );
    }

    for ( i = 2; i < ac; i++ ) {
	new->cc_value[ i - 2 ] = strdup( av[ i ] );
	new->cc_next = NULL;
    }

    return( new );
}

    static int
parseConfig_( char *path )
{
    SNET		*sn;
    char		**av, *line;
    int			ac;
    int			linenum = 0;
    struct cosigncfg	*cc_new;
    struct chosts 	*ch_new;

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
	
	if ( strcmp( av[ 0 ],"config" ) == 0 ) {
	    if ( ac < 3 ) {
		fprintf( stderr, "%s: line %d, "
			"wrong number of args for config keyword\n",
			path, linenum );
		return( -1 );
	    }
	    cc_new = processConfigLine( ac, av );
	    if ( cc_new ) {
		addConfig( cc_new );
	    }
	} else if ( strcmp( av[ 0 ],"include" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d, "
			"wrong number args to include keyword\n",
			path, linenum );
		continue;
	    }
	    if ( parseConfig_( av[1] )) {
		fprintf(stderr,"\tincluded from %s line %d\n", path, linenum);
		return( -1 );
	    }
	} else {
	    /* Normal ACL like command */
	    ch_new = chosts_read( ac, av, path, linenum );
	    if ( ch_new ) {
		addchost( ch_new );
	    }
	}
    }
    /* check for net_error */
    return( snet_close( sn ));
}

/*
 * File format is
 *	keyword hostname
 *	keyword hostname T
 *	keyword hostname P path
 *	keyword hostname TP path
 *	config key value
 *	include configfilepath
 */
    int
parseConfig( char *path )
{
    struct chosts	**cur_ch;
    struct cosigncfg 	**cur_cc;

    if ( authlist != NULL ) {
	chosts_free( );
    }

    if ( cfg != NULL ) {
	freeConfig();
    }

    cur_ch = &authlist;
    cur_cc = &cfg;

    return parseConfig_( path );
}

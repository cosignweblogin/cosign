/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "wildcard.h"
#include "conf.h"
#include "argcargv.h"

struct cosigncfg {
    char 		*cc_key;
    char 		**cc_value;
    unsigned int 	cc_numval;
    struct cosigncfg 	*cc_next;
};

static struct authlist		*authlist = NULL, *new_authlist;
struct factorlist	 	*factorlist = NULL;
static struct servicelist	*servicelist = NULL, *new_servicelist;;
static struct matchlist		*certlist = NULL;
static struct matchlist		*negotiatemap = NULL;
static struct matchlist		*authenticatorlist = NULL;
static struct cosigncfg 	*cfg = NULL, *new_cfg;


static struct matchlist		defmysqlauthenticator = {
    "mysql", "(.+@.+)", "$1", "friend", NULL,
};

static struct matchlist		defkerberosauthenticator = {
    "kerberos", "([^@]+)", "$1", "", NULL,
};

char			*suffix = NULL;

    static void
config_free( struct cosigncfg **p )
{
    struct cosigncfg *q;

    while ( *p ) {
	free( (*p)->cc_key );
	free( (*p)->cc_value );
	q = (*p)->cc_next;
	free( *p );
	*p = q;
    }
    return;
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

    struct servicelist *
service_find( char *cookie, regmatch_t matches[], int nmatch )
{
    struct servicelist	*cur = NULL;
    regex_t		preg;
    char		error[ 1024 ];
    int			rc;

    if ( nmatch < 1 || matches == NULL ) {
	/* require at least one regmatch_t in the array */
	return( NULL );
    }

    for ( cur = servicelist; cur != NULL; cur = cur->sl_next ) {
	if (( rc = regcomp( &preg, cur->sl_cookie, REG_EXTENDED )) != 0 ) {
	    regerror( rc, &preg, error, sizeof( error ));
	    fprintf( stderr, "regcomp %s failed: %s\n", cur->sl_cookie, error );
	    continue;
	}

	if (( rc = regexec( &preg, cookie, nmatch, matches, 0 )) == 0 ) {
	    /* only match whole service names */
	    if ( matches[ 0 ].rm_so == 0 &&
		    matches[ 0 ].rm_eo == strlen( cookie )) {
		regfree( &preg );
		break;
	    }
	} else if ( rc != REG_NOMATCH ) {
	    regerror( rc, &preg, error, sizeof( error ));
	    fprintf( stderr, "regexec failed: %s\n", error );
	}

	regfree( &preg );
    }

    return( cur );
}

    struct authlist *
authlist_find( char *hostname )
{
    struct authlist	*cur = NULL;
    regex_t		preg;
    regmatch_t		matches[ 1 ];
    char		error[ 1024 ];
    int			rc;

    for ( cur = authlist; cur != NULL; cur = cur->al_next ) {
	/* case-insensitive matching */
	if (( rc = regcomp( &preg, cur->al_hostname,
		REG_EXTENDED | REG_ICASE )) != 0 ) {
	    regerror( rc, &preg, error, sizeof( error ));
	    fprintf( stderr, "regcomp %s failed: %s\n", cur->al_hostname,error);
	    return( NULL );
	}

	if (( rc = regexec( &preg, hostname, 1, matches, 0 )) == 0 ) {
	    if ( matches[ 0 ].rm_so == 0 &&
			matches[ 0 ].rm_eo == strlen( hostname )) {
		regfree( &preg );
		break;
	    }
	} else if ( rc != REG_NOMATCH ) {
	    regerror( rc, &preg, error, sizeof( error ));
	    fprintf( stderr, "regexec failed: %s\n", error );
	}
	regfree( &preg );
    }

    return( cur );
}

    int
match_substitute( char *pattern, int len, char *buf,
	int nmatch, regmatch_t matches[], char *source )
{
    char	*p, *b, *bufend, *numend;
    int		i, matchlen;

    bufend = buf + len;

    for ( p = pattern, b = buf; *p != '\0'; p++ ) {
	if ( *p == '$' ) {
	    ++p;
	    if ( *p == '\0' ) {
		return( -1 );
	    }

	    if ( *p == '$' ) {
		if ( b + 1 >= bufend ) {
		    return( -1 );
		}
		*b++ = '$';
		continue;
	    }

	    i = strtol( p, &numend, 10 );
	    if ( p == numend ) {
		if ( b + 1 >= bufend ) {
		    return( -1 );
		}
		*b++ = '$';
		continue;
	    }
	    if ( i >= nmatch ) {
		if ( b + 1 + ( numend - p ) >= bufend ) {
		    return( -1 );
		}
		*b++ = '$';
		strncpy( b, p, numend - p );
		b += numend - p;
		continue;
	    }
	    matchlen = matches[ i ].rm_eo - matches[ i ].rm_so;
	    if ( b + matchlen >= bufend ) {
		return( -1 );
	    }
	    strncpy( b, source + matches[ i ].rm_so, matchlen );
	    b += matchlen;
	} else {
	    if ( b + 1 >= bufend ) {
		return( -1 );
	    }
	    *b++ = *p;
	}
    }

    if ( b + 1 >= bufend ) {
	return( -1 );
    }
    *b = '\0';
    return( 0 );
}

    int
matchlist_process(struct matchlist *ml, char *userstring, char **l, char **r )
{
    regex_t preg;
    char error[ 1024 ];
    int rc;
    regmatch_t          matches[ 3 ];
    static char         login[ 130 ];   /* "64@64\0" */
    static char         realm[ 256 ];   /* big */

    if (( rc = regcomp( &preg, ml->ml_regexp, REG_EXTENDED )) != 0 ) {
	regerror( rc, &preg, error, sizeof( error ));
        fprintf( stderr, "%s: %s", ml->ml_regexp, error );
        return ( -1 );
    }

    if (( rc = regexec( &preg, userstring, 3, matches, 0 )) == 0 ) {
	if ( matches[ 0 ].rm_so != 0 ||
		matches[ 0].rm_eo != strlen( userstring )) {
	    return ( -1 );
	}

	if ( match_substitute( ml->ml_login, sizeof( login ), login,
		3, matches, userstring ) != 0 ) {
	     fprintf( stderr, "match string (%s) or login (%s) too big.\n",
		    userstring, ml->ml_login );
	     return( -1 );
	}
	*l = login;

	if ( match_substitute( ml->ml_realm, sizeof( realm ), realm,
		3, matches, userstring ) != 0 ) {
	    fprintf( stderr, "match string (%s) or realm (%s) too big.\n",
		    userstring, ml->ml_realm );
	    return( -1 );
	}
	*r = realm;

	return( 0 );
    }
    if ( rc != REG_NOMATCH ) {
	regerror( rc, &preg, error, sizeof( error ));
	fprintf( stderr, "%s: %s", ml->ml_regexp, error );
    }
    return( -1 );
}

    int
x509_translate( char *subject, char *issuer, char **l, char **r )
{
    struct matchlist	*cur = NULL;

    for ( cur = certlist; cur != NULL; cur = cur->ml_next ) {
	if ( strcmp( cur->ml_key, issuer ) != 0 ) {
	    continue;
	}
	if ( matchlist_process( cur, subject, l, r ) == 0 ) {
	    break;
	}
    }

    if ( cur == NULL ) {
	fprintf( stderr, "subject %s with issuer %s didn't match.\n",
		subject, issuer );
	return ( -1 );
    }

    return( 0 );
}

    int
negotiate_translate( char *remote_user, char **l, char **r )
{
    if ( negotiatemap != NULL ) {
	return( matchlist_process(negotiatemap, remote_user, l, r ));
    } else {
	return( -1 );
    }
}

	int
pick_authenticator( char *login, char **type, char **l, char **r,
	struct matchlist **pos )
{
    if ( authenticatorlist == NULL ) {
	authenticatorlist = &defmysqlauthenticator;
	authenticatorlist->ml_next = &defkerberosauthenticator;
    }

    if ( *pos == NULL ) {
	*pos = authenticatorlist;
    } else {
	*pos = (*pos)->ml_next;
    }

    while ( *pos != NULL ) {

	if ( matchlist_process( *pos, login, l, r ) == 0 ) {
	    *type = (*pos)->ml_key;
	    break;
	} else {
	    *pos = (*pos)->ml_next;
	}
    }

    if ( (*pos) == NULL ) {
	fprintf( stderr, "Couldn't identify an authenticator for '%s'\n",
		 login);
	return( -1 );
    }

    return( 0 );
}

    static void
authlist_free( struct authlist **al )
{
    struct authlist 	*cur, *next;
    struct proxies	*pcur, *pnext;

    for ( cur = *al; cur != NULL; cur = next ) {
	free( cur->al_hostname );
	for ( pcur = cur->al_proxies; pcur != NULL; pcur = pnext ) {
	    free( pcur->pr_hostname );
	    free( pcur->pr_cookie );
	    pnext = pcur->pr_next;
	    free( pcur );
	}
	next = cur->al_next;
	free( cur );
    }
    *al = NULL;
}

    static void
servicelist_free( struct servicelist **sl )
{
    struct servicelist	*scur, *snext;
    int			i;

    for ( scur = *sl; scur != NULL; scur = snext ) {
	free( scur->sl_cookie );
	free( scur->sl_wkurl );
	if ( scur->sl_cookiesub != NULL ) {
	    free( scur->sl_cookiesub );
	}
	for ( i = 0; scur->sl_factors[ i ] != NULL; i++ ) {
	    free( scur->sl_factors[ i ] );
	}
	snext = scur->sl_next;
	free( scur );
    }
    *sl = NULL;
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
    int			ac, i, j;
    int			linenum = 0;
    int			insert = 1;
    struct cosigncfg	*cc_new, **cc_cur;
    struct authlist 	*al_new, **al_cur;
    struct servicelist	*sl_new, **sl_cur;
    struct matchlist	*cl_new, **cl_cur;
    struct factorlist	*fl_new, **fl_cur;

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
	    for ( cc_cur = &new_cfg; (*cc_cur) != NULL;
		    cc_cur = &(*cc_cur)->cc_next )
		;

	    cc_new->cc_next = *cc_cur;
	    *cc_cur = cc_new;

	} else if ( strcmp( av[ 0 ], "include" ) == 0 ) {
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

	} else if ( strcmp( av[ 0 ], "reauth" ) == 0 ) {
	    if ( ac < 2 ) {
		fprintf( stderr, "line %d: keyword reauth"
			" takes at least 2 args\n", linenum );
		return( -1 );
	    }
	    for ( sl_new = new_servicelist; sl_new != NULL;
		    sl_new = sl_new->sl_next ) {
		if ( strcmp( sl_new->sl_cookie, av[ 1 ] ) == 0 ) {
		    break;
	    }
	    }
	    if ( sl_new == NULL ) {
		fprintf( stderr, "line %d: keyword reauth requires "
			"a prior matching service entry\n", linenum );
		return( -1 );
	    }
	    sl_new->sl_flag |= SL_REAUTH;

	    if (( ac - 2 ) >= COSIGN_MAXFACTORS ) {
		fprintf( stderr, "line %d:"
			" too many factors (%d > %d) to keyword reauth\n",
			linenum, ac - 2, COSIGN_MAXFACTORS - 1 );
		return( -1 );
	    }
	    for ( j = 0, i = 2; i < ac; i++, j++ ) {
		if (( sl_new->sl_factors[ j ] = strdup( av[ i ] )) == NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
	    }
	    sl_new->sl_factors[ j ] = NULL;

	} else if ( strcmp( av[ 0 ], "cert" ) == 0 ) {
	    if ( ac != 5 ) {
		fprintf( stderr, "line %d: keyword cert takes 5 args\n",
			linenum );
		return( -1 );
	    }
	    if (( cl_new = (struct matchlist *)malloc(
		    sizeof( struct matchlist ))) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_key = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_regexp = strdup( av[ 2 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_login = strdup( av[ 3 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_realm = strdup( av[ 4 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    cl_new->ml_next = NULL;

	    for ( cl_cur = &certlist; (*cl_cur) != NULL;
		    cl_cur = &(*cl_cur)->ml_next )
		;

	    cl_new->ml_next = *cl_cur;
	    *cl_cur = cl_new;

	} else if ( strcmp( av[ 0 ], "negotiate" ) == 0 ) {
	    if ( ac != 4 ) {
		fprintf( stderr, "line %d: keyword negotiate takes 4 args\n",
			linenum );
		return( -1 );
	    }
	    if ( negotiatemap != NULL ) {
		fprintf( stderr, "line %d:"
			" keyword negotiate may only be used once\n", linenum );
		return( -1 );
	    }
	    if (( negotiatemap = (struct matchlist *)malloc(
		    sizeof( struct matchlist ))) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    negotiatemap->ml_key = NULL;
	    if (( negotiatemap->ml_regexp = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( negotiatemap->ml_login = strdup( av[ 2 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( negotiatemap->ml_realm = strdup( av[ 3 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    negotiatemap->ml_next = NULL;

	} else if ( strcmp( av[ 0 ], "passwd" ) == 0 ) {
	    if ( ac != 5 ) {
		fprintf( stderr, "line %d: keyword authenticator takes 5 args\n",
			linenum );
		return( -1 );
	    }
	    if (( cl_new = (struct matchlist *)malloc(
		    sizeof( struct matchlist ))) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_key = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_regexp = strdup( av[ 2 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_login = strdup( av[ 3 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->ml_realm = strdup( av[ 4 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    cl_new->ml_next = NULL;

	    for ( cl_cur = &authenticatorlist; (*cl_cur) != NULL;
		    cl_cur = &(*cl_cur)->ml_next )
		;

	    cl_new->ml_next = *cl_cur;
	    *cl_cur = cl_new;

	} else if ( strcmp( av[ 0 ], "factor" ) == 0 ) {
	    if ( ac < 3 ) {
		fprintf( stderr, "line %d:"
			" keyword factor takes at least 2 args\n",
			linenum );
		return( -1 );
	    }

	    if (( fl_new = malloc( sizeof( struct factorlist ))) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( fl_new->fl_path = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    fl_new->fl_flag = 0;
	    for ( i = 2; *av[ i ] == '-'; i++ ) {
		if ( strcmp( av[ i ], "-2" ) == 0 ) {
		    fl_new->fl_flag = 2;
		} else {
		    fprintf( stderr, "line %d:"
			    " unknown flag %s to keyword factor\n",
			    linenum, av[ i ] );
		    return( -1 );
		}
	    }
	    if (( ac - i ) < 1 ) {
		fprintf( stderr, "line %d:"
			" keyword factor requires at least one form field\n",
			linenum );
		return( -1 );
	    }
	    if (( ac - i ) > FL_MAXFORMFIELDS - 1 ) {
		fprintf( stderr, "line %d:"
			" too many form fields (%d > %d) to keyword factor\n",
			linenum, ac - i, FL_MAXFORMFIELDS - 1 );
		return( -1 );
	    }
	    for ( j = 0; i < ac; i++, j++ ) {
		if (( fl_new->fl_formfield[ j ] = strdup( av[ i ] )) == NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
	    }
	    fl_new->fl_formfield[ j ] = NULL;

	    for ( fl_cur = &factorlist; (*fl_cur) != NULL;
		    fl_cur = &(*fl_cur)->fl_next )
		;

	    fl_new->fl_next = *fl_cur;
	    *fl_cur = fl_new;

	} else if ( strcmp( av[ 0 ], "suffix" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "line %d: keyword suffix takes 1 arg\n",
			linenum );
		return( -1 );
	    }
	    if ( suffix != NULL ) {
		fprintf( stderr, "line %d: keyword suffix already set to %s\n",
			linenum, suffix );
		return( -1 );
	    }
	    if (( suffix = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }

	} else if ( strcmp( av[ 0 ], "proxy" ) == 0 ) {
	    /*
	     * "proxy" requires a prior entry in the authlist
	     * for the hostname given as the second argument.
	     */
	    if ( ac != 3 ) {
		fprintf( stderr, "line %d: keyword proxy takes 2 args\n",
			linenum );
		return( -1 );
	    }

	    for ( al_new = new_authlist; al_new != NULL;
		    al_new = al_new->al_next ) {
		if ( strcmp( av[ 1 ], al_new->al_hostname ) == 0 ) {
		    break;
		}
	    }
	    if ( al_new == NULL ) {
		fprintf( stderr, "line %d: keyword proxy requires "
			"prior matching service entry\n", linenum );
		return( -1 );
	    }
	    if ( al_new->al_key != SERVICE ) {
		fprintf( stderr, "line %d: proxy must be a SERVICE\n",
			linenum );
		return( -1 );
	    }

	    if ( proxy_read( al_new, av[ 2 ] ) < 0 ) {
		fprintf( stderr, "proxy read failed line %d\n",
			linenum );
		return( -1 ); 
	    }
	    al_new->al_flag |= AL_PROXY;

	} else {
	    /*
	     * The rest of these all create an entry to be inserted into
	     * the new_authlist.
	     */
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
		if ( ac != 5 && ac != 6 ) {
		    fprintf( stderr,
			"line %d: keyword service takes 5 or 6 args\n",
			linenum );
		    return( -1 );
		}


		if (( sl_new = (struct servicelist *)malloc(
				sizeof( struct servicelist ))) == NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
		sl_new->sl_next = NULL;
		sl_new->sl_factors[ 0 ] = NULL;
		sl_new->sl_cookiesub = NULL;
		sl_new->sl_flag = 0;

		/*
		 * new service lines look like this:
		 *
		 * # type  cookie      location handler  flags  cn  cookie
		 * service cosign-(.*) https://$1.domain.edu/cosign/valid \
		 *	flags	(.*)\.domain\.edu [ cosign-$1 ]
		 */
		if (( sl_new->sl_cookie = strdup( av[ 1 ] )) == NULL ) {
		    perror( "strdup" );
		    return( -1 );
		} 

		if (( sl_new->sl_wkurl = strdup( av[ 2 ] )) == NULL ) {
		    perror( "strdup" );
			return( -1 );
		    }

		if ( strchr( av[ 3 ], 'T' ) != 0 ) {
		    sl_new->sl_flag |= SL_TICKET;
		} 
		if ( strchr( av[ 3 ], '2' ) != 0 ) {
		    sl_new->sl_flag |= SL_SCHEME_V2;
		}

		if ( ac == 6 ) {
		    /* custom cookie substitution pattern */
		    if (( sl_new->sl_cookiesub = strdup( av[ 5 ] )) == NULL ) {
			perror( "strdup" );
			return( -1 ); 
		    }
		}

		/*
		 * look for a prior entry for this hostname.
		 * if not found, allocate a new one. in both
		 * cases, point the new servicelist entry's
		 * sl_auth field to al_new.
		 *
		 */
		insert = 1;
		for ( al_new = new_authlist; al_new != NULL;
			al_new = al_new->al_next ) {
		    if ( al_new->al_key != SERVICE ) {
			continue;
		    }
		    if ( strcmp( al_new->al_hostname, av[ 4 ] ) == 0 ) {
			insert = 0;
			break;
		    }
		}
		if ( al_new == NULL ) {
		    if (( al_new = (struct authlist *)malloc(
				    sizeof( struct authlist ))) == NULL ) {
			perror( "malloc" );
			return( -1 );
		    }
		    if (( al_new->al_hostname = strdup( av[ 4 ] )) == NULL ) {
			perror( "strdup" );
			return( -1 );
		    }
		    al_new->al_key = SERVICE;
		    al_new->al_flag = 0;
		    al_new->al_proxies = NULL;
		    al_new->al_next = NULL;
		}
		sl_new->sl_auth = al_new;

		/* insert the new service at the end of the list */
		for ( sl_cur = &new_servicelist; *sl_cur != NULL;
			sl_cur = &( *sl_cur )->sl_next )
		    ;

		sl_new->sl_next = *sl_cur;
		*sl_cur = sl_new;

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
		al_new->al_proxies = NULL;

	    } else {
		fprintf( stderr, "invalid keyword line %d: %s\n",
			linenum, av[ 0 ] );
		return( -1 );
	    }

	    
	    if ( insert ) {
	    for ( al_cur = &new_authlist; (*al_cur) != NULL;
		    al_cur = &(*al_cur)->al_next )
		;

	    al_new->al_next = *al_cur;
	    *al_cur = al_new;
	    }
	}
    }

    return( snet_close( sn ));
}


/*
 * File format is
 *	cgi hostname
 *	service hostname 0
 *	service hostname T
 *	service hostname 2
 *	service hostname T2
 *	proxy hostname proxyfilepath
 *	reauth cookie factor1 factor2 ... factorMAX
 *	notauth hostname
 *	set key value
 *	include configfilepath
 */
    int
cosign_config( char *path )
{
    struct authlist	*old_authlist;
    struct servicelist	*old_servicelist;
    struct cosigncfg	*old_cfg;

    new_authlist = NULL;
    new_servicelist = NULL;
    new_cfg = NULL;
    
    if ( read_config( path ) != 0 ) {
	if ( new_authlist != NULL ) {
	    authlist_free( &new_authlist );
	}

	if ( new_servicelist != NULL ) {
	    servicelist_free( &new_servicelist );
	}

	if ( new_cfg != NULL ) {
	    config_free( &new_cfg );
	}
	return( -1 );
    }

    old_cfg = cfg;
    old_servicelist = servicelist;
    old_authlist = authlist;

    cfg = new_cfg;
    servicelist = new_servicelist;
    authlist = new_authlist;

    if ( old_authlist != NULL ) {
	authlist_free( &old_authlist );
    }
    if ( old_servicelist != NULL ) {
	servicelist_free( &old_servicelist );
    }
    if ( old_cfg != NULL ) {
	config_free( &old_cfg );
    }

    return( 0 );
}

    int
cosign_ssl( char *cryptofile, char *certfile, char *capath, SSL_CTX **ctx )
{
    SSL_CTX	*tmp, *old;
    struct stat	st;

    if ( stat( capath, &st ) != 0 ) {
	fprintf( stderr, "stat %s: %s\n", capath, strerror( errno ));
	return( 1 );
    }

    if ( access( cryptofile, R_OK ) != 0 ) {
        perror( cryptofile );
        return( 1 );
    }

    if ( access( certfile, R_OK ) != 0 ) {
        perror( certfile );
        return( 1 );
    }

    if ( S_ISDIR( st.st_mode )) {
	if ( access( capath, X_OK ) != 0 ) {
	    perror( capath );
	    return( 1 );
	}
    } else {
	if ( access( capath, R_OK ) != 0 ) {
	    perror( capath );
	    return( 1 );
	}
    }

    if (( tmp = SSL_CTX_new( SSLv23_method())) == NULL ) {
	fprintf( stderr, "SSL_CTX_new: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	return( 1 );
    }

    if ( SSL_CTX_use_PrivateKey_file( tmp, cryptofile, SSL_FILETYPE_PEM )
	    != 1 ) {
	fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	return( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( tmp, certfile ) != 1) {
	fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL));
	return( 1 );
    }
    if ( SSL_CTX_check_private_key( tmp ) != 1 ) {
	fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	return( 1 );
    }
    if ( S_ISDIR( st.st_mode )) {
	if ( SSL_CTX_load_verify_locations( tmp, NULL, capath ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_load_verify_location: %s\n",
		    ERR_error_string( ERR_get_error(), NULL ));
	    return( 1 );
	}
    } else if ( SSL_CTX_load_verify_locations( tmp, capath, NULL ) != 1 ) {
	fprintf( stderr, "SSL_CTX_load_verify_location: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	return( 1 );
    }

    SSL_CTX_set_verify( tmp,
	    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    old = *ctx;
    *ctx = tmp;

    if ( old != NULL ) {
	SSL_CTX_free( old );
    }

    return( 0 );
}

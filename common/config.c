/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
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
#include "config.h"
#include "argcargv.h"

struct authlist		*authlist = NULL, *new_authlist;
struct servicelist	*servicelist = NULL;
struct certlist		*certlist = NULL;
struct cosigncfg 	*cfg = NULL, *new_cfg;

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
service_find( char *cookie )
{
    struct servicelist	*cur = NULL;

    for ( cur = servicelist; cur != NULL; cur = cur->sl_next ) {
	if ( strcmp( cur->sl_cookie, cookie ) == 0 ) {
	    break;
	}
    }
    return( cur );
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

    int
x509_substitute( char *pattern, int len, char *buf,
	int nmatch, regmatch_t matches[], char *source )
{
    char	*p, *q;
    int		i, j;

    /* need to do bounds checking */

    for ( p = pattern, q = buf; *p != '\0'; p++ ) {
	if ( *p == '$' ) {
	    p++;
	    if ( *p == '\0' || *p == '$' ) {
		*q++ = '$';
	    }
	    if ( isdigit( *p )) {
		/* need to write our own? */
		i = strtol( p, NULL, 10 );
		if ( i >= nmatch ) {
		    *q++ = '$';
		    *q++ = *p;
		    continue;
		}
		j = matches[ i ].rm_eo - matches[ i ].rm_so;
		strncpy( q, source + matches[ i ].rm_so, j );
		q += j;
	    } else {
		*q++ = '$';
		*q++ = *p;
	    }
	} else {
	    *q++ = *p;
	}
    }

    *q = '\0';
    return( 0 );
}

    int
x509_translate( char *subject, char *issuer, char **l, char **r )
{
    struct certlist	*cur = NULL;
    regex_t		preg;
    char		error[ 1024 ];
    int			rc;
    regmatch_t		matches[ 3 ];
    static char		login[ 130 ];	/* "64@64\0" */
    static char		realm[ 256 ];	/* big */

    for ( cur = certlist; cur != NULL; cur = cur->cl_next ) {
	if ( strcmp( cur->cl_issuer, issuer ) != 0 ) {
	    continue;
	}
	if (( rc = regcomp( &preg, cur->cl_subject, 0 )) != 0 ) {
	    regerror( rc, &preg, error, sizeof( error ));
	    fprintf( stderr, "%s: %s", cur->cl_subject, error );
	    continue;
	}
	if (( rc = regexec( &preg, subject, 3, matches, 0 )) == 0 ) {
	    if ( matches[ 0 ].rm_so != 0 ||
		    matches[ 0 ].rm_eo != strlen( subject )) {
		continue;
	    }
	    break;
	}
	if ( rc != REG_NOMATCH ) {
	    regerror( rc, &preg, error, sizeof( error ));
	    fprintf( stderr, "%s: %s", cur->cl_subject, error );
	}
    }

    if ( cur == NULL ) {
	fprintf( stderr, "%s: issuer not found.\n", issuer );
	return ( -1 );
    }

    if ( x509_substitute( cur->cl_login, sizeof( login ), login,
	    3, matches, subject ) != 0 ) {
	fprintf( stderr, "subject (%s) or login (%s) too big.\n",
		subject, cur->cl_login );
	return( -1 );
    }
    *l = login;

    if ( x509_substitute( cur->cl_realm, sizeof( realm ), realm,
	    3, matches, subject ) != 0 ) {
	fprintf( stderr, "subject (%s) or realm (%s) too big.\n",
		subject, cur->cl_realm );
	return( -1 );
    }
    *r = realm;

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
	    pnext = pcur;
	    free( pcur );
	}
	next = cur->al_next;
	free( cur );
    }
    *al = NULL;
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
    struct servicelist	*sl_new, **sl_cur;
    struct certlist	*cl_new, **cl_cur;

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

	} else if ( strcmp( av[ 0 ], "cookie" ) == 0 ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "line %d: keyword cookie takes 3 args\n",
			linenum );
		return( -1 );
	    }
	    if ( strcmp( av[ 2 ], "reauth" ) != 0 ) {
		fprintf( stderr, "line %d: unknown argument to cookie: %s\n",
			linenum, av[ 2 ] );
		return( -1 );
	    }
	    if (( sl_new = (struct servicelist *)malloc(
		    sizeof( struct servicelist ))) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( sl_new->sl_cookie = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    sl_new->sl_flag = SL_REAUTH;
	    sl_new->sl_next = NULL;

	    for ( sl_cur = &servicelist; (*sl_cur) != NULL;
		    sl_cur = &(*sl_cur)->sl_next )
		;

	    sl_new->sl_next = *sl_cur;
	    *sl_cur = sl_new;

	} else if ( strcmp( av[ 0 ], "cert" ) == 0 ) {

	    if (( ac != 5 ) && ( ac != 6 )) {
		fprintf( stderr, "line %d: keyword cert takes 5 or 6 args\n",
			linenum );
		return( -1 );
	    }
	    if (( cl_new = (struct certlist *)malloc(
		    sizeof( struct certlist ))) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->cl_issuer = strdup( av[ 1 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->cl_subject = strdup( av[ 2 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->cl_login = strdup( av[ 3 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if (( cl_new->cl_realm = strdup( av[ 4 ] )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	    }
	    if ( ac == 6 ) {
		if (( cl_new->cl_type = strdup( av[ 5 ] )) == NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
	    } else {
		cl_new->cl_type = NULL;
	    }
	    cl_new->cl_next = NULL;

	    for ( cl_cur = &certlist; (*cl_cur) != NULL;
		    cl_cur = &(*cl_cur)->cl_next )
		;

	    cl_new->cl_next = *cl_cur;
	    *cl_cur = cl_new;
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

	    
	    for ( al_cur = &new_authlist; (*al_cur) != NULL;
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
    struct authlist	*old_authlist;
    struct cosigncfg	*old_cfg;

    new_authlist = NULL;
    new_cfg = NULL;
    
    if ( read_config( path ) != 0 ) {
	if ( new_authlist != NULL ) {
	    authlist_free( &new_authlist );
	}

	if ( new_cfg != NULL ) {
	    config_free( &new_cfg );
	}
	return( -1 );
    }

    old_cfg = cfg;
    old_authlist = authlist;

    cfg = new_cfg;
    authlist = new_authlist;

    if ( old_authlist != NULL ) {
	authlist_free( &old_authlist );
    }

    if ( old_cfg != NULL ) {
	config_free( &old_cfg );
    }

    return( 0 );
}

    int
cosign_ssl( char *cryptofile, char *certfile, char *cadir, SSL_CTX **ctx )
{
    SSL_CTX	*tmp, *old;

    if ( access( cryptofile, R_OK ) != 0 ) {
        perror( cryptofile );
        return( 1 );
    }

    if ( access( certfile, R_OK ) != 0 ) {
        perror( certfile );
        return( 1 );
    }

    if ( access( cadir, X_OK ) != 0 ) {
        perror( cadir );
        return( 1 );
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
    if ( SSL_CTX_load_verify_locations( tmp, NULL, cadir ) != 1 ) {
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

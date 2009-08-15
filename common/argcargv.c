/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
 * Return parsed argc/argv from the net.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "argcargv.h"

#define ACV_ARGC		10
#define ACV_WHITE		(0)
#define ACV_WORD		(1<<0)
#define ACV_DQUOTE		(1<<1)
static ACAV *acavg = NULL;

    ACAV *
acav_alloc( void )
{
    ACAV *acav;

    if ( ( acav = (ACAV*)malloc( sizeof( ACAV ) ) ) == NULL ) {
	return( NULL );
    }
    if ( ( acav->acv_argv =
	    (char **)malloc( sizeof(char *) * ( ACV_ARGC ) ) ) == NULL ) {
	free( acav );
	return( NULL );
    }
    acav->acv_argc = ACV_ARGC;
    acav->acv_flags = ACV_FLAG_DEFAULTS;

    return( acav );
}

/*
 * acav->acv_argv = **argv[] if passed an ACAV
 */

    int
acav_parse( ACAV *acav, char *line, char **argv[] )
{
    int		ac;
    int		state;

    if ( acav == NULL ) {
	if ( acavg == NULL ) {
	    acavg = acav_alloc();
	}
	acav = acavg;
    }

    ac = 0;
    state = ACV_WHITE;

    while ( *line != '\0' ) {
	switch ( *line ) {
	case ' ' :
	case '\t' :
	case '\n' :
	    if ( state == ACV_WORD ) {
		*line = '\0';
		state = ACV_WHITE;
	    }
	    break;

	case '"' :
	    if ( acav->acv_flags & ACV_FLAG_QUOTE ) {
		memmove( line, line + 1, strlen( line ));
		if ( state & ACV_DQUOTE ) {
		    state &= ~ACV_DQUOTE;
		    continue;	/* don't increment line */
		} else {
		    state |= ACV_DQUOTE;
		}
	    }
	    /* fall through */

	default :
	    if (( acav->acv_flags & ACV_FLAG_BACKSLASH ) && *line == '\\' ) {
		memmove( line, line + 1, strlen( line ));
	    }
	    if ( !( state & ACV_WORD )) {
		acav->acv_argv[ ac++ ] = line;
		if ( ac >= acav->acv_argc ) {
		    /* realloc */
		    if (( acav->acv_argv = (char **)realloc( acav->acv_argv,
			    sizeof( char * ) * ( acav->acv_argc + ACV_ARGC )))
			    == NULL ) {
			return( -1 );
		    }
		    acav->acv_argc += ACV_ARGC;
		}
		state |= ACV_WORD;
	    }
	}

	line++;
    }

    acav->acv_argv[ ac ] = NULL; 
    *argv = acav->acv_argv;
    return( ac );
}

    int
acav_free( ACAV *acav )
{
    free( acav->acv_argv );
    free( acav );

    return( 0 );
}

#ifdef notdef
main( int ac, char *av[] )
{
    char	**nav;
    int		nac, i;

    printf( "av: %s\n", av[ 1 ] );

    nac = acav_parse( NULL, av[ 1 ], &nav );

    for ( i = 0; i < nac; i++ ) {
	printf( "nav[ %d ] = %s\n", i, nav[ i ] );
    }
    exit( 0 );
}
#endif // notdef

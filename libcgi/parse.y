%{

    #include <stdio.h>
    #include <string.h>

    #include "cgi.h"

    extern struct cgi_list	*yy_cl;
    struct cgi_list		*c;
    int				found;
    int				syntax = 0;

%}

%union {
    char		*STRING;
    char		CHAR;
};

%token t_IDENT
%token t_CHAR
%token t_EQ
%token t_AMP

%type <STRING> t_IDENT field string
%type <CHAR> t_CHAR

%start line

%%

line
	: pairs
		{
		    if ( syntax != 0 ) {
			return( CGI_E_SYNTAX );
		    }
		}
	;
pairs
	: pairs t_AMP pair
	| pair
	| error
	|
	;

pair
	: field t_EQ string
		{
		    found = 0;

		    /* search cgi list for the key */
		    for ( c = yy_cl; c->cl_key != NULL; c++ ) {
			if ( strcmp( c->cl_key, $1 ) == 0 ) {
			    /* matching key */
			    found = 1;

			    /* XXX BEHAVIOR
			     * we'll keep the first key defined, toss all
			     * others.
			     */

			    if ( c->cl_data == NULL ) {
				if (( c->cl_data = strdup( $3 )) == NULL ) {
				    return( CGI_E_SYSCALL );
				}

				if ( cgi_debug != 0 ) {
				    printf( "defined key:\t'%s'\tdata:\t'%s'\n",
					    $1, $3 );
				}

			    } else {
				if ( cgi_debug != 0 ) {
				    printf( "extra key:\t'%s'\tdata:\t'%s'\n",
					    $1, $3 );
				}
			    }
			    break;
			}
		    }

		    if ( found == 0 ) {
			/* XXX BEHAVIOR
			 * discard non-matching keys */
			if ( cgi_debug != 0 ) {
			    printf( "undefined key:\t'%s'\tdata:\t'%s'\n",
				    $1, $3 );
			}
		    }
		}
	;

string
	: field
		{
		    $$ = $1;
		}

	|
		{
		    $$ = "\0";		/* NULL string */
		}
	;

field
	: field t_IDENT
		{
		    if (( $$ = concat( $1, $2 )) == NULL ) {
			return( CGI_E_SYSCALL );
		    }
		}

	| field t_CHAR
		{
		    if (( $$ = stradd( $1, $2 )) == NULL ) {
			return( CGI_E_SYSCALL );
		    }
		}

	| t_IDENT
		{
		    if (( $$ = strdup( $1 )) == NULL ) {
			return( CGI_E_SYSCALL );
		    }
		}

	| t_CHAR
		{
		    if (( $$ = (char*)malloc( 2 )) == NULL ) {
			return( CGI_E_SYSCALL );
		    }
		    sprintf( $$, "%c", $1 );
		}
	;
%%


    char *
stradd( char *a, char b )
{
    int			x;
    char		*c;

    x = strlen( a );
    x += 2;

    if (( c = (char*)malloc( x )) == NULL ) {
	return( NULL );
    }

    sprintf( c, "%s%c", a, b );

    free( a );

    return( c );
}

    char *
concat( char *a, char *b )
{
    int			x;
    char		*c;

    x = strlen( a ) + strlen( b );

    if (( c = (char*)malloc( x + 1 )) == NULL ) {
	return( NULL );
    }

    sprintf( c, "%s%s", a, b );

    free( a );

    return( c );
}


    void
yyerror( const char *msg )
{
    syntax++;
}

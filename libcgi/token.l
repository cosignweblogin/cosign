%{

#include <stdlib.h>

#include "y.tab.h"
#include "cgi.h"

%}

String		[A-Za-z0-9_@.*-]+
Meta		"%"[A-Fa-f0-7][A-Fa-f0-9]

%%

{String}	{
		    // printf( "token:\tIDENT:\t%s\n", yytext );
		    yylval.STRING = yytext;
		    return( t_IDENT );
		}

{Meta}		{
		    // printf( "token:\tMETA:\t%c\n",
		    //	    strtol( yytext + 1, NULL, 16 ));
		    yylval.CHAR = strtol( yytext + 1, NULL, 16 );
		    return( t_CHAR );
		}

"&"		{
		    return( t_AMP );
		}

"="		{
		    return( t_EQ );
		}

[+]		{
		    // printf( "token:\tCHAR:\t \n" );
		    yylval.CHAR = ' ';
		    return( t_CHAR );
		}

.		{
		    // printf( "token:\tCHAR:\t%s\n", yytext );
		    return( *yytext );
		}

%%

    int
yywrap( void )
{
    return( 1 );
}

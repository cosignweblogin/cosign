#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "subfile.h"

    void
subfile( char *filename, struct subfile_list *sl, int nocache )
{
    FILE	*fs;
    int 	c, i, j;
    char	nasties[] = "<>(){}[]'`\" \\";

    if ( nocache ) {
	fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Cache-Control: no-store, no-cache, must-revalidate\n"
		"Cache-Control: pre-check=0, post-check=0, max-age=0\n"
		"Pragma: no-cache\n", stdout );
    }

    fputs( "Content-type: text/html\n\n", stdout );

    if (( fs = fopen( filename, "r" )) == NULL ) {
	perror( filename );
	exit( 1 );
    }

    while (( c = getc( fs )) != EOF ) {
	if ( c == '$' ) {
	    if (( c = getc( fs )) == EOF ) {
		putchar( '$' );
		break;
	    }

	    if ( c == '$' ) {
		putchar( c );
		continue;
	    }

	    for ( i = 0; sl[ i ].sl_letter != '\0'; i++ ) {
		if ( sl[ i ].sl_letter == c ) {
		    break;
		}
	    }
	    if ( sl[ i ].sl_letter == '\0' ) {
		putchar( '$' );
		putchar( c );
	    } else if ( sl[ i ].sl_data != NULL ) {
		if ( sl[ i ].sl_type == SUBF_STR ) {
		    printf( "%s", sl[ i ].sl_data );
		} else if ( sl[ i ].sl_type == SUBF_STR_ESC ) {

		    /* block XSS attacks while printing */
                    for ( j = 0; j < strlen( sl[ i ].sl_data ); j++ ) {
                        if ( strchr( nasties, sl[ i ].sl_data[ j ] ) != NULL ||
                                sl[ i ].sl_data[ j ] <= 0x1F ||
				sl[ i ].sl_data[ j ] >= 0x7F ) {

			    printf( "%%%x", sl[ i ].sl_data[ j ] );
                        } else {
                            putc( sl[ i ].sl_data[ j ], stdout );
                        }
		    }
		}
	    }
	} else {
	    putchar( c );
	}
    }

    if ( fclose( fs ) != 0 ) {
	perror( filename );
    }

    return;
}

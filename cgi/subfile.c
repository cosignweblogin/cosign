#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __STDC__
#include <stdarg.h>
#else /* __STDC__ */
#include <varargs.h>
#endif /* __STDC__ */

#include "subfile.h"

    void
subfile( char *filename, struct subfile_list *sl, int opts, ... )
{
    FILE	*fs;
    int 	c, i, j;
    char	nasties[] = "<>(){}[]'`\" \\";
    va_list	vl;

    /*
     * close stdin to avoid "ap_content_length_filter: apr_bucket_read()"
     * errors, which occur in apache2 environments when a cgi starts
     * writing a response before processing all input. see:
     *
     * https://issues.apache.org/bugzilla/show_bug.cgi?id=44782
     */
    (void)close( 0 );

    if ( opts & SUBF_OPT_NOCACHE ) {
	fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Cache-Control: no-store, no-cache, must-revalidate\n"
		"Cache-Control: pre-check=0, post-check=0, max-age=0\n"
		"Pragma: no-cache\n", stdout );
    }
    if ( opts & SUBF_OPT_SETSTATUS ) {
	/* set HTTP Status header */
#ifdef __STDC__
	va_start( vl, opts );
#else /* __STDC__ */
	va_start( vl );
#endif /* __STDC__ */
	i = va_arg( vl, int );
	va_end( vl );
	if ( i < 200 || i > 600 ) {
	    /* unlikely http status code */
	    i = 200;
	}
	printf( "Status: %d\n", i );
    }
    if ( opts & SUBF_OPT_LOG ) {
#define SL_TITLE	1
#define SL_ERROR	4
	if ( sl[ SL_TITLE ].sl_data && sl[ SL_ERROR ].sl_data ) {
	    fprintf( stderr, "cosign cgi: %s: %s\n", sl[ SL_TITLE ].sl_data,
			sl[ SL_ERROR ].sl_data );
	}
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

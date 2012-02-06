/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
 * to do:
 * eliminate post_read
 * specify directory
 * address ENOMEM in post_getline
 * fix query_string. check cgi_get/cgi_post  can we have a null string? 
 */

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <limits.h>

#include "cgi.h"

#ifndef min
#define min( x, y ) (( x ) > ( y ) ? ( y ) : ( x ))
#endif

#ifdef EBUG
#define DEBUG(x)      (x)
#else
#define DEBUG(x)
#endif

static char * post_getline( CGIHANDLE * );
static int mp_read( CGIHANDLE *, char *, int, char * );
static int cgi_querystring( char *, struct cgi_list * );

/*
 * Global variable indicating whether or not mp_get_file()
 * should clobber an existing file during a file upload.
 * This flag should be set in the user-defined f_init() function.
 */
int cgi_file_clobber = 0;

/*
 * Get a null-terminated line of input, handle CR/LF issues.
 * Note that net_getline() returns information from a common area which
 * may be overwritten by subsequent calls.
 */

    static char *
post_getline( CGIHANDLE *cgi )
{
    char		*eol, *tmp;
    int			rc;

DEBUG( fprintf( stderr, "DB: in post_getline\n" ));
    for ( eol = cgi->ci_cur; ; eol++) {
	if ( eol >= cgi->ci_end ) {				/* fill */
	    /* pullup */
	    if ( cgi->ci_cur > cgi->ci_buf ) {
		if ( cgi->ci_cur < cgi->ci_end ) {
		    memmove( cgi->ci_buf, cgi->ci_cur,
			    (unsigned)( cgi->ci_end - cgi->ci_cur ));
		}
		eol = cgi->ci_end = cgi->ci_buf + ( cgi->ci_end - cgi->ci_cur );
		cgi->ci_cur = cgi->ci_buf;
	    }

	    /* expand */
	    if ( cgi->ci_end == ( cgi->ci_buf + cgi->ci_buflen )) {
		if (( cgi->ci_maxlen != 0 ) && ( cgi->ci_buflen  >= 
			cgi->ci_maxlen )) {
		    errno = ENOMEM;
		    return( NULL );
		}
		if (( cgi->ci_buf = (char *)realloc( cgi->ci_buf,
			cgi->ci_buflen + CGI_BUFLEN )) == NULL ) {
		    return( NULL );
		}
		cgi->ci_buflen += CGI_BUFLEN;
		eol = cgi->ci_end = cgi->ci_buf + ( cgi->ci_end - cgi->ci_cur );
		cgi->ci_cur = cgi->ci_buf;
	    }

	    if (( rc = read( 0, cgi->ci_end, cgi->ci_buflen - 
			( cgi->ci_end - cgi->ci_buf ))) < 0 ) {
		CGI_SYSERR( cgi, "read" );
		return( NULL );
	    }
	    if ( rc == 0 ) {	/* EOF */
		if ( cgi->ci_end > cgi->ci_cur ) {
		    break;  
		}
		return( NULL );
	    }
	    cgi->ci_end += rc;
	}

	if ( *eol == '\r' || *eol == '\0' ) {
	    cgi->ci_state = CGIIN_FUZZY;
	    break;
	}
	if ( *eol == '\n' ) {
	    if ( cgi->ci_state == CGIIN_FUZZY ) {
		cgi->ci_state = CGIIN_BOL;
		cgi->ci_cur = eol + 1;
		continue;
	    }
	    break;
	}
	cgi->ci_state = CGIIN_IN;
    }

    *eol = '\0';
    tmp = cgi->ci_cur;
    cgi->ci_cur = eol + 1;
DEBUG( fprintf( stderr, "DB: in post_getline, returning %s\n", tmp ));
    return( tmp );
}


   CGIHANDLE * 
cgi_init( void ) 
{
    CGIHANDLE 	*cgi;

DEBUG( fprintf( stderr, "DB: in cgi_init\n" ));
    if (( cgi = (CGIHANDLE *)malloc( sizeof( CGIHANDLE ))) == NULL ) {
	perror( "cgi_init: malloc CGIHANDLE" );
	return( NULL );
    }
    memset( cgi, 0, sizeof( CGIHANDLE ));

    if (( cgi->ci_buf = (char *)malloc( CGI_BUFLEN )) == NULL ) {
	goto error;
    }

    cgi->ci_cur = cgi->ci_end = cgi->ci_buf;
    cgi->ci_buflen = CGI_BUFLEN;
    cgi->ci_state = CGIIN_BOL;

    return( cgi );

error:
    CGI_SYSERR( cgi, "malloc" );
    CGI_LOGERR( cgi );
    if ( cgi ) {
	free( cgi );
    }

    return( NULL );
}

    void
cgi_free( CGIHANDLE *cgi )
{
DEBUG( fprintf( stderr, "DB: in cgi_free\n" ));
    if ( cgi != NULL ) {
        if ( cgi->ci_buf != NULL) { 
	    free( cgi->ci_buf );
	    cgi->ci_buf = NULL;
	}
	free( cgi );
    }
    return;
}

    int
cf_free( struct cgi_file *cf )
{
    struct cgi_file	*cur;

DEBUG( fprintf( stderr, "DB: in cf_free\n" ));
    if ( cf != NULL ) {
	for ( cur = cf; cf != NULL; cf = cur ) {
	    if ( cf->cf_name != NULL) {
		free( cf->cf_name );
	    }
	    if ( cf->cf_tmp != NULL) {
		free( cf->cf_tmp );
	    }
	    if ( cf->cf_ctype != NULL) {
		free( cf->cf_ctype );
	    }
	    if ( cf->cf_status != NULL) {
		free( cf->cf_status );
	    }
	    cur = cf->cf_next;
	    free( cf );
	}
    }

    return( 0 );
}

    int
cgi_cl_free( struct cgi_list cl[] ) 
{
    int	i;
    for( i = 0; cl[i].cl_key != NULL; i++ ) {
	if ( cl[i].cl_type == CGI_TYPE_FILE ) {
	    cf_free( cl[i].cl_data );
	} else if ( cl[i].cl_type == CGI_TYPE_STRING ) {
	    free( cl[i].cl_data );
	} else if ( cl[i].cl_type == CGI_TYPE_EMAIL ) {
	    free( cl[i].cl_data );
	}
    }
    return( 0 );
}

    int
cgi_cl_print( struct cgi_list cl[] )
{
    int	i;
    struct cgi_file *ptr;

    printf( "\n\n" );
    for( i = 0; cl[i].cl_key != NULL; i++ ) {
	printf( "key %d : %s\n", i, cl[i].cl_key );
	if ( cl[i].cl_type == CGI_TYPE_FILE ) {
	    if ( cl[i].cl_data != NULL ) {
		for ( ptr = cl[i].cl_data; ptr != NULL; ptr = ptr->cf_next ) { 
	    	    printf( "type: file\ndata: file %s of length %d\n\n", 
				    ((struct cgi_file *)ptr)->cf_name, 
				    ((struct cgi_file *)ptr)->cf_size );
	    	    printf( "temporary name is %s\n\n", 
				    ((struct cgi_file *)ptr)->cf_tmp ); 
		    if ( ptr->cf_status != NULL ) {
		        printf( "error_string: %s\n", ptr->cf_status );
		    }
	        }
	    } else {
	        printf( "type: string\ndata: (null)\n\n");
	    }
	} else if ( cl[i].cl_type == CGI_TYPE_STRING ) {
	    printf( "type: string\ndata: %s\n\n", (char *)cl[i].cl_data );
	} else if ( cl[i].cl_type == CGI_TYPE_EMAIL ) {
	    printf( "type: email\ndata: %s\n\n", (char *)cl[i].cl_data );
	} else {
	    printf( "type: unknown\n\n" );
	}
    }
    fprintf( stderr, "%d values\n\n", i );
    return( 0 );
}

    static int
mp_read( CGIHANDLE *cgi, char *buf, int buflen, char *boundary )
{
    int		read_chars = 0;
    int		skipcrlf = 0;
    int		rc;
    int		test_len;
    int		bound_len;
    char	*search_p;

DEBUG( fprintf( stderr, "DB: in mp_read\n" ));
    bound_len = strlen( boundary );
    if ( cgi->ci_buflen < bound_len + 4 ) {
	CGI_PARSERR( cgi, "mp_read: provided buffer too small" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if ( cgi->ci_state == CGIIN_FUZZY ) {
	cgi->ci_cur++;
	cgi->ci_state = CGIIN_BOL;
    }

    if ( cgi->ci_end - cgi->ci_cur < bound_len + 4 ) {
	if ( cgi->ci_cur > cgi->ci_buf ) {
	    if ( cgi->ci_cur < cgi->ci_end ) {
		memmove( cgi->ci_buf, cgi->ci_cur, 
		    (unsigned)( cgi->ci_end - cgi->ci_cur )); 
	    }
	    cgi->ci_end = cgi->ci_buf + ( cgi->ci_end - cgi->ci_cur );
	    cgi->ci_cur = cgi->ci_buf;
	}

	if (( rc = read( 0, cgi->ci_end, cgi->ci_buflen - 
		    ( cgi->ci_end - cgi->ci_buf ))) <= 0 ) {
	    CGI_PARSERR( cgi, "mp_read: did not get any characters" );
	    CGI_LOGERR( cgi );
	    return( -1 );
	}
	cgi->ci_end += rc;
    }

    if (( *cgi->ci_cur == '-' ) && ( *( cgi->ci_cur + 1 ) == '-' )) {
	if ( memcmp(( cgi->ci_cur + 2 ), boundary, bound_len ) == 0 ) {
	    return( 0 );
	} 
    }

    test_len = min( cgi->ci_end - cgi->ci_cur, buflen );
    search_p = cgi->ci_cur;
    while (( search_p = memchr( search_p, '\r', test_len )) != NULL ) {

	if (( cgi->ci_end - search_p ) < 2 ) {
	    break;
	}
	if (( *search_p == '\r' ) && ( *(search_p + 1) == '\n' )) {
	    break;
	}

	test_len = min( cgi->ci_end - search_p, buflen );
	search_p++;
    }

    if ( search_p == NULL ) {
	search_p = cgi->ci_end;
    }

    if (( cgi->ci_end - search_p ) >= ( bound_len + 4 )) {
	if ((( *( search_p + 2 ) == '-' ) && ( *( search_p + 3 ) == '-' )) &&
		(( memcmp(( search_p + 4 ), boundary, bound_len )) == 0 )) {
	    skipcrlf = 2;
	} else {
	    search_p += 2;
	}
    }

    read_chars = min( search_p - cgi->ci_cur, buflen );
    memcpy( buf, cgi->ci_cur, read_chars );
    cgi->ci_cur += read_chars + skipcrlf;
DEBUG( fprintf( stderr, "DB: returning read_chars; read_chars is %d\n", 
       read_chars ));
    return( read_chars );
}

    int
mp_get_file( struct cgi_file *upfile, CGIHANDLE *cgi, char *boundary, struct function *func )
{
    int			file_content;
    char		file_buffer[ CGI_BUFLEN ];
    int			returned = 0;

DEBUG( fprintf( stderr, "DB: in mp_get_file\n" ));

    upfile->cf_size = 0;

    // write the file out directly 
    if (( file_content = open( upfile->cf_tmp, O_WRONLY|O_CREAT|
                               ((cgi_file_clobber) ? 0 : O_EXCL),
                               0666 ))
		== -1 ) {
	CGI_SYSERR( cgi, "open" );
	CGI_LOGERR( cgi );
	/* if file exists we abort - how do we report it */
	upfile->cf_status =  malloc(strlen (strerror( cgi->ci_errno)) + 1 );
	strcpy( upfile->cf_status, strerror(cgi->ci_errno) );
	goto error2;
    }

    while(( returned = mp_read( cgi, file_buffer, CGI_BUFLEN, boundary )) > 0 ) {
	if (( write( file_content, file_buffer, returned )) != returned ) {
	    CGI_SYSERR( cgi, "write" );
	    CGI_LOGERR( cgi );
	    upfile->cf_status =  malloc(strlen (strerror( cgi->ci_errno)) + 1 );
	    strcpy( upfile->cf_status, strerror(cgi->ci_errno) );
	    close( file_content );
	    goto error1;
	}
	upfile->cf_size += returned;
	if ( func != NULL ) {
	    if ((func->f_progress( upfile->cf_name, returned ) != 0)) {
		DEBUG( fprintf( stderr, "DB: f_progress failed\n" ));
		upfile->cf_status = strdup("not successful");
		goto error1;
	    }
	}

    }

    close( file_content );

    if ( returned != 0 ) {
	goto error1;
    }

    /* went well */
    upfile->cf_status = strdup("successful" );
    return( 0 );

error1:
    unlink( upfile->cf_tmp );

error2:
    upfile->cf_size = 0;
    return( -1 );
}

    int
cgi_multipart( CGIHANDLE *cgi, struct cgi_list cl[], char *dir, struct function *func )
{
    char 	*line, *filename, *filetype, *ptr;
    char	*request_method;
    char	key[CGI_LINLEN];
    char	boundary[CGI_LINLEN];
    char	end_boundary[CGI_LINLEN];
    char	junkbuf[CGI_BUFLEN];
    int		i, rc, boundlen;
    struct cgi_file *upfile, *cur_upfile;

DEBUG( fprintf( stderr, "DB: in cgi_multipart\n" ));

    if (( request_method = getenv( "REQUEST_METHOD" )) == NULL ) {
	CGI_PARSERR( cgi, line );
	CGI_LOGERR( cgi );
	return( -1 );
    }
    if (( strcasecmp( request_method, "POST" )) != 0 ) {
	CGI_PARSERR( cgi, "request method not POST" );
	CGI_LOGERR( cgi );
	return( -1 );
    }
DEBUG( fprintf( stderr, "DB: request method is %s\n", request_method ));
    if (( line = getenv( "CONTENT_TYPE" )) == NULL ) {
	CGI_PARSERR( cgi, "null" );
	CGI_LOGERR( cgi );
	return( -1 );
    }
DEBUG( fprintf( stderr, "DB: content type is %s\n", line ));
    if (( strstr( line, "multipart/form-data" )) == NULL ) {
	CGI_PARSERR( cgi, line );
	CGI_LOGERR( cgi );
	return( -1 );
    }
    strtok( line, "=");
    line = (char *)strtok( NULL, "\0" );
DEBUG( fprintf( stderr, "DB: line is ? %s", line ));

    snprintf( end_boundary, sizeof(end_boundary), "%s--", line );
    strcpy( boundary, line );
    boundlen = strlen( boundary );

     
    for( ;; ) {
DEBUG( fprintf( stderr, "\nDB: in for\n" ));

	if ((( line = post_getline( cgi )) == NULL ) || 
	       ( strlen( line ) > CGI_LINLEN )) {
	    CGI_PARSERR( cgi, line );
	    CGI_LOGERR( cgi );
	    return( -1 );
	}
    

	if ( strncmp( line + 2, end_boundary, boundlen + 2 ) == 0 ) {
DEBUG( fprintf( stderr, "DB: found end boundary\n" ));
	    return( 0 );
	}

	if ( strncmp( line + 2, boundary, boundlen ) != 0 ) {
	    CGI_PARSERR( cgi, line );
	    CGI_LOGERR( cgi );
	    return( -1 );
//	    if (( strlen( line + 2 ) >= boundlen + 2 ) && 
//		    ( strncmp( line + 2 + boundlen, "--", 2 ) == 0 )) {
//		return( 0 );
//	    }
	    //continue;
	    // or get line?  one loop = one pair?
	} 

	if (( line = post_getline( cgi )) == NULL || 
	    strlen( line ) > CGI_LINLEN ) {
	    CGI_PARSERR( cgi, line );
	    CGI_LOGERR( cgi );
	    return( -1 );
	}

	*key = '\0';
	do {
	    if (( strncasecmp( line, "Content-Disposition: form-data;", 31 ))
		    == 0 ) {
		strtok( line, "\"");
		strcpy( key, (char *)strtok( NULL, "\"" ));
		line = strtok( NULL, "\0" );
		if ( line != NULL ) {
		    /* must be a file */
		    filename = strdup( line );
		}
	    } else if (( strncasecmp( line, "Content-Type:", 13 )) == 0 ) {
		filetype = strdup( line );
	    }
	    //skipping the blank line for non-file data
	    if (( line = post_getline( cgi )) == NULL ||
			strlen( line ) > CGI_LINLEN ) {
		CGI_PARSERR( cgi, line );
		CGI_LOGERR( cgi );
		return( -1 );
	    }

	// while you have lines 
	} while ( *line != '\0' );

DEBUG( fprintf( stderr, "DB key is %s\n", key ));
	for( i = 0; cl[i].cl_key != NULL; i++ ) {
	    if ( strcmp( cl[i].cl_key, key ) == 0 ) {
		break;
	    }
	}

	if ( cl[i].cl_key == NULL ) {
	    // skip to boundary
	    while (( rc = mp_read( cgi, junkbuf, CGI_BUFLEN, boundary ))) {
	    	if( rc  <  0 ) {
		    return( -1 );
		}
	    }
	    continue;
	}

	if ( cl[i].cl_type == CGI_TYPE_FILE ) {
	    strtok( filename, "\"" );
	    filename = strtok( NULL, "\"" );
	    if( filename == "" || filename == NULL ) {
		// skip to boundary
		while (( rc = mp_read( cgi, junkbuf, CGI_BUFLEN, boundary ))) {
		    if( rc  <  0 ) {
			return( -1 );
		    }
		}
		continue;
	    }
	    // make sure we have a clean filename 
	    if ( strstr( filename, ".." ) != NULL ) {
		fprintf( stderr, "found ..\n" );
		return( -1 );
	    }
	    ptr = strdup( filename );
	    ptr = strtok( ptr, "\\" );
	    while ( ptr != NULL ) {
		filename = strdup( ptr );
		ptr = strtok( NULL, "\\" );
	    }

	    // function initialize 
	    if ( func != NULL ) {
		if (( func->f_init( &dir, cl )) != 0 ) {
		    DEBUG( fprintf( stderr, "DB: f_init failed\n" ));
		    return( -1 );
		}
	    }

	    if (( upfile = (struct cgi_file *)malloc( sizeof( struct cgi_file ))) == NULL ) {
		CGI_SYSERR( cgi, "malloc" );
		CGI_LOGERR( cgi );
		return( -1 );
	    }
	    upfile->cf_name = strdup( filename );
	    upfile->cf_ctype = strdup( filetype );
	    upfile->cf_status = NULL;

	    if (( upfile->cf_tmp = malloc((strlen(dir)) + (strlen(upfile->cf_name)) + 2 )) == NULL ) {
	    }
	    sprintf( upfile->cf_tmp, "%s/%s", dir, upfile->cf_name );

	    upfile->cf_next = NULL;
	    if ( cl[i].cl_data == NULL ) {
		cl[i].cl_data = upfile;
	    } else {
		cur_upfile->cf_next = upfile;
	    }
	    cur_upfile = upfile;

DEBUG( fprintf( stderr, "DB: calling mp_get_file\n" ));
	    if(( mp_get_file( upfile, cgi, boundary, func )) != 0 ) {
		return( -1 );
	    } 
	    continue;
	}

	if (( line = post_getline( cgi )) == NULL || 
		strlen( line ) > CGI_LINLEN ) {
	    CGI_PARSERR( cgi, line );
	    CGI_LOGERR( cgi );
	    return( -1 );
	}
	if ( *line == '\0' ) {
	    cl[i].cl_data = NULL;
	} else {
	    cl[i].cl_data = (char *)strdup( line );
	}

    } /* for */
}
    char *
cgi_unescape( char *raw )
{
    char    *unesc;
    char    *ptr;
    char	buf[ 3 ];

    ptr = unesc = raw;
    for ( ; *raw != '\0'; raw++ ) {
	switch( *raw ) {
        case '+':
            *ptr = ' ';
            ptr++;
            break;

        case '%':
            raw++;
	    if (( *raw == '\0' ) || (*(raw + 1) == '\0' )) {
		return( NULL );
	    }
	    buf[ 0 ] = *raw++;
	    buf[ 1 ] = *raw;
	    buf[ 2 ] = '\0';
	    *ptr++ = (char)strtol( buf, NULL, 16 );
            break;

        default:
            *ptr = *raw;
            ptr++;
	}
    }
    *ptr = '\0';

    return( unesc );
}

// should return cl == NULL if no line... check b4 first strtok!!!!!
    static int
cgi_querystring( char *line, struct cgi_list *cl )
{
    char 	*key, *data;
    int		i;
DEBUG( fprintf( stderr, "DB: in cgi_qs\n" ));
    for ( key = strtok( line, "&" ); key != NULL; key = strtok( NULL, "&" )) {

	if (( data = strchr( key, '=' )) == NULL ) {
	    return( -1 );
	}
	*data++ = '\0';
	if (( key = cgi_unescape( key )) == NULL ) {
	    return( -1 );
	}
	for ( i = 0; cl[ i ].cl_key != NULL; i++ ) {
	    if ( strcmp( cl[ i ].cl_key, key ) == 0 ) {
		if (( data == NULL ) || ( *data == '\0' )) {
		    cl[ i ].cl_data = NULL;
		    break;
		}
		if (( data = cgi_unescape( data )) == NULL ) {
		    return( -1 );
		}
		if (( cl[ i ].cl_data = strdup( data )) == NULL ) {
		    return( -1 );
		}
		break;
	    }
	}
    }
    return( 0 );
}

    int
cgi_get( CGIHANDLE *cgi, struct cgi_list *cl )
{
    char	*line;

DEBUG( fprintf( stderr, "DB: in cgi_get\n" ));
    if (( line = getenv( "QUERY_STRING" )) == NULL ) {
	CGI_PARSERR( cgi, "no query_string environment variable" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if ( *line == '\0' ) {
	CGI_PARSERR( cgi, "NULL query_string environment variable" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if (( cgi_querystring( line, cl )) != 0 ) {
	CGI_PARSERR( cgi, line );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    return( 0 );
    
}

    int
cgi_post( CGIHANDLE *cgi, struct cgi_list *cl )
{
    char	*line;
    char	*request_method;
    char	*content_type;

DEBUG( fprintf( stderr, "DB: in cgi_post\n" ));
    if (( request_method = getenv( "REQUEST_METHOD" )) == NULL ) {
	CGI_PARSERR( cgi, "no request_method" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if (( strcasecmp( request_method, "POST" )) != 0 ) {
	CGI_PARSERR( cgi, "method not POST" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if (( content_type = getenv( "CONTENT_TYPE" )) == NULL ) {
	CGI_PARSERR( cgi, "no content_type" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if (( strcmp( content_type, "application/x-www-form-urlencoded" )) != 0 ) {
	CGI_PARSERR( cgi, "content_type application/x-www-form-urlencoded" );
	CGI_LOGERR( cgi );
	return( -1 );
    }

    if (( line = post_getline( cgi )) == NULL ) {
	return( -1 );
    }
    if (( cgi_querystring( line, cl )) != 0 ) {
	return( -1 );
    }

    return( 0 );
}

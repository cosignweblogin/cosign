/*
 * Copyright (c) 1995,1997 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

typedef struct {
    char        *ci_buf;
    char        *ci_end;
    char        *ci_cur;
    int         ci_buflen;
    int         ci_maxlen;
    int         ci_state;
    int		ci_errno;
    int         ci_errtype;
    int		ci_errline;
    char        *ci_errstring;

} CGIHANDLE;

struct cgi_list {
    char        *cl_key;
    int		cl_type;
    void        *cl_data;
};

struct cgi_file {
    char		*cf_name;
    char		*cf_tmp;
    char		*cf_ctype;
    int			cf_size;
    char		*cf_status;
    struct cgi_file 	*cf_next;
};

struct function {
    int  (*f_init)( char **, struct cgi_list * );
    int  (*f_progress)( char *, int );
};

CGIHANDLE * cgi_init( void );
void cgi_free( CGIHANDLE * );
int cf_free( struct cgi_file * );
int cgi_cl_free( struct cgi_list * );
int cgi_cl_print( struct cgi_list * );
int mp_get_file( struct cgi_file *, CGIHANDLE *, char *, struct function * );
int cgi_multipart(CGIHANDLE *, struct cgi_list *, char *, struct function * );
char * cgi_unescape( char * );
int cgi_get( CGIHANDLE *, struct cgi_list * );
int cgi_post( CGIHANDLE *, struct cgi_list * );

#define CGI_BUFLEN      8192
#define CGI_LINLEN      512
#define CGI_IOVCNT      128
#define CGI_STDIN       0

#define CGIIN_BOL       0
#define CGIIN_FUZZY     1
#define CGIIN_IN        2

#define CGI_TYPE_UNDEF	-1
#define CGI_TYPE_FILE	0
#define CGI_TYPE_STRING	1
#define CGI_TYPE_EMAIL	2

#define CGI_ERR_PARSE	0
#define CGI_ERR_SYS	1

#define CGI_ERRTYPE(c)		((c)->ci_errtype)
#define CGI_ERRSTRING(c)	((c)->ci_errstring)
#define CGI_ERRLINE(c)		((c)->ci_errline)

#define CGI_LOGERR(c)		{ \
	if ( (c)->ci_errtype == CGI_ERR_PARSE ) { \
		fprintf( stderr, "Parse error at line %d:\n%s\n", (c)->ci_errline,(c)->ci_errstring ); \
	} else { \
		fprintf( stderr, "System error at line %d:\n%s: %s\n", (c)->ci_errline, (c)->ci_errstring, strerror( (c)->ci_errno )); \
        } \
}

#define CGI_PARSERR( c, l )	{ \
	(c)->ci_errtype = CGI_ERR_PARSE; \
	(c)->ci_errstring = (l); \
	(c)->ci_errline = __LINE__; }

#define CGI_SYSERR( c, s )	{ \
	(c)->ci_errtype = CGI_ERR_SYS; \
	(c)->ci_errno = errno; \
	(c)->ci_errstring = (s); \
	(c)->ci_errline = __LINE__; }

/*
 * Global variable indicating whether or not mp_get_file()
 * should clobber an existing file during a file upload.
 * This flag should be set in the user-defined f_init() function.
 */
int cgi_file_clobber;

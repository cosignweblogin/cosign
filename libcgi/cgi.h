/*****     cgi.h     *****/

#define	CGI_STDIN		0
#define	CGI_POST		1
#define	CGI_GET			2

struct cgi_list {
    char			*cl_key;
    char			*cl_data;
};

extern int			cgi_debug;

int cgi_info( int, struct cgi_list * );
char * cgi_strerror( int );
void cgi_contents( struct cgi_list * );

#define	CGI_E_SYSCALL	1	/* System memory error */
#define	CGI_E_SYNTAX	2	/* Syntax error in parse */
#define	CGI_E_REQUEST	3	/* Invalid request method */
#define	CGI_E_POST	4	/* CGI request method must be POST */
#define	CGI_E_GET	5	/* CGI request method must be GET */
#define	CGI_E_METHOD	6	/* Method argument out of range */
#define	CGI_E_LIST	7	/* List argument NULL */
#define	CGI_E_MAX	8

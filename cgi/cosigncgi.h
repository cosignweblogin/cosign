struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    struct connlist     *conn_next;
};

struct subparams {
    char	*sp_ref;
    char	*sp_service;
    char	*sp_factor;
    int		sp_reauth;
    int		sp_ipchanged;
};

//int	mkcookie( int, char * );
struct connlist * connlist_setup( char *, unsigned short );

#define COSIGN_ERROR            -1
#define COSIGN_OK               0
#define COSIGN_RETRY            1
#define COSIGN_LOGGED_OUT       2

#define COSIGN_CGI_OK                 0
#define COSIGN_CGI_ERROR              1
#define COSIGN_CGI_PASSWORD_EXPIRED   2 

#define LOGIN_ERROR_HTML        "login_error.html"
#define EXPIRED_ERROR_HTML      "expired_error.html"
#define ERROR_HTML     		"error.html"
#define LOGIN_HTML      	"login.html"
#define REAUTH_HTML     	"reauth.html"
#define REDIRECT_HTML		"redirect.html"
#define VERIFY_LOGOUT		"verify-logout.html"

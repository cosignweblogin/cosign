typedef struct {
    char                *host;
    char                *service;
    char		*siteentry;
    int			public;
    char                *redirect;
    char                *posterror;
    unsigned short      port;
    int                 protect;
    int                 configured;
    struct connlist     *cl;
    SSL_CTX		*ctx;
    char		*cert;
    char		*key;
    char		*cadir;
    char		*filterdb;
    char		*proxydb;
    char		*tkt_prefix;
    int                 http;
    int			proxy;
    int			expiretime;
#ifdef KRB
#ifdef GSS
    int			gss;
#endif /* GSS */
    int			krbtkt;
    int			krb524;
#endif /* KRB */
} cosign_host_config;

struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    struct connlist     *conn_next;
};

#define COSIGN_ERROR		-1
#define COSIGN_OK		0
#define COSIGN_RETRY		1
#define COSIGN_LOGGED_OUT	2

int cosign_cookie_valid( cosign_host_config *, char *, struct sinfo *, char *,
	server_rec * );
int cosign_check_cookie( char *, struct sinfo *, cosign_host_config *, int,
	server_rec * );
int teardown_conn( struct connlist *, server_rec * );

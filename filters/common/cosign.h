typedef struct {
    char                *host;
    char                *service;
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


int cookie_valid( cosign_host_config *, char *, struct sinfo *, char * );
int check_cookie( char *, struct sinfo *, cosign_host_config *, int );
int teardown_conn( struct connlist * );

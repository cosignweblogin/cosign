typedef struct {
    char                *host;
    char                *service;
    char                *redirect;
    char                *posterror;
    unsigned short      port;
    int                 protect;
    int                 configured;
    struct connlist     *cl;
} cosign_host_config;


struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    struct connlist     *conn_next;
};


int cookie_valid( struct connlist **, char *, struct sinfo * );
int choose_conn( char *, struct sinfo *, struct connlist ** );
int teardown_conn( );

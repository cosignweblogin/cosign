typedef struct {
    char                *host;
    char                *service;
    char                *redirect;
    char                *posterror;
    unsigned short      port;
    int                 protect;
    int                 configured;
    struct sinlist      *sl;
} cosign_host_config;

struct sinlist {
    struct sockaddr_in  s_sin;
    int                 s_copied;
    struct sinlist      *s_next;
};

struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    int                 conn_flag;
    struct connlist     *conn_next;
};

#define CONN_UNUSED	( 1 << 0 )
#define CONN_OPEN	( 1 << 1 )
#define CONN_PROB	( 1 << 2 )

int cookie_valid( struct sinlist *, char * );
int copy_connections( struct sinlist * );
int teardown_conn( );

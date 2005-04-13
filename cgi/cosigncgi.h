struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    struct connlist     *conn_next;
};

int	mkcookie( int, char * );
struct connlist * connlist_setup( char *, unsigned short );

#define COSIGN_ERROR            -1
#define COSIGN_OK               0
#define COSIGN_RETRY            1
#define COSIGN_LOGGED_OUT       2

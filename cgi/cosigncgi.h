struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    struct connlist     *conn_next;
};

int	mkcookie( int, char * );
struct connlist * connlist_setup( char *, unsigned short );

struct cl {
    struct sockaddr_in  cl_sin;
    SNET                *cl_sn;
    struct cl		*cl_next;
    time_t		cl_last_time;
};

int connect_sn( struct cl *, SSL_CTX *, char * );
int close_sn( struct cl *);

struct cl {
    struct sockaddr_in  cl_sin;
    SNET                *cl_sn;
    SNET                *cl_psn;
    struct cl		*cl_next;
    union {
	time_t		cu_last_time;
#define cl_last_time	cl_u.cu_last_time
	pid_t		cu_pid;
#define cl_pid		cl_u.cu_pid
    } cl_u;
};

int connect_sn( struct cl *, SSL_CTX *, char * );
int close_sn( struct cl *);

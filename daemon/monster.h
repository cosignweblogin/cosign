/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

struct connlist {
    struct sockaddr_in  cl_sin;
    SNET                *cl_sn;
    SNET                *cl_psn;
    struct connlist	*cl_next;
    union {
	time_t		cu_last_time;
#define cl_last_time	cl_u.cu_last_time
	pid_t		cu_pid;
#define cl_pid		cl_u.cu_pid
    } cl_u;
    struct rate		cl_pushpass;
    struct rate		cl_pushfail;
};

int connect_sn( struct connlist *, SSL_CTX *, char *, int );
int close_sn( struct connlist *);

/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

struct cinfo {
    int		ci_version;
    int		ci_state;
    char	ci_ipaddr[ 256 ];	/* longer than necessary */
    char	ci_ipaddr_cur[ 256 ];	/* longer than necessary */
    char	ci_user[ 130 ];		/* "64@64\0" */
    char	ci_realm[ 256 ];	/* longer than necessary */
    char	ci_ctime[ 12 ];		
    char	ci_krbtkt[ MAXPATHLEN ];
    time_t	ci_itime;
};

int do_logout( char * );
int service_to_login( char *, char * );
int read_cookie( char *, struct cinfo * );

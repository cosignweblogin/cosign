/*
 * Copyright (c) 1995,2001 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else __STDC__
#define ___P(x)		()
#endif __STDC__

typedef struct {
    int		sn_fd;
    char	*sn_rbuf;
    int		sn_rbuflen;
    char	*sn_rend;
    char	*sn_rcur;
    int		sn_maxlen;
    int		sn_rstate;
    char	*sn_wbuf;
    int		sn_wbuflen;
    int		sn_flag;
} SNET;

#define snet_fd( sn )	((sn)->sn_fd)

int	snet_eof ___P(( SNET * ));
SNET	*snet_attach ___P(( int, int ));
SNET	*snet_open ___P(( char *, int, int, int ));
int	snet_close ___P(( SNET * ));
int	snet_writef ___P(( SNET *, char *, ... ));
char	*snet_getline ___P(( SNET *, struct timeval * ));
char	*snet_getline_multi ___P(( SNET *, void (*)(char *),
		struct timeval * ));
int	snet_read ___P(( SNET *, char *, int, struct timeval * ));
int	snet_write ___P(( SNET *, char *, int, struct timeval * ));
int	snet_starttls ___P(( SNET * ));

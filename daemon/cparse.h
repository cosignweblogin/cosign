struct cinfo {
    int		ci_version;
    int		ci_state;
    char	ci_ipaddr[ 256 ];
    char	ci_user[ 256 ];
    char	ci_realm[ 256 ];
    char	ci_ctime[ 12 ];
    char	ci_krbtkt[ 24 ];
    time_t	ci_itime;
};

int do_logout( char * );
int service_to_login( char *, char * );
int read_cookie( char *, struct cinfo * );

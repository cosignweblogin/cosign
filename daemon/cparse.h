struct cinfo {
    int		ci_version;
    int		ci_state;
    char	ci_ipaddr[ 256 ];
    char	ci_user[ 32 ];
    char	ci_realm[ 256 ];
    char	ci_ctime[ 12 ];
    time_t	ci_itime;
};

int read_a_cookie( char *, struct cinfo * );

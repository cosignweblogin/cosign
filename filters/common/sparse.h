struct sinfo {
    char	si_ipaddr[ 256 ];
    char	si_user[ 32 ];
    char	si_realm[ 256 ];
    time_t	si_itime;
};

int read_secant( char *, struct sinfo * );

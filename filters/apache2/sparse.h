struct sinfo {
    char	si_ipaddr[ 256 ];
    char	si_user[ 131 ];
    char	si_realm[ 256 ];
    char	si_krb5tkt[ 24 ];
    char	si_krb4tkt[ 24 ];
    time_t	si_itime;
};

int read_scookie( char *, struct sinfo * );

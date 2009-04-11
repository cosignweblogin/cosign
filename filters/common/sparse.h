struct sinfo {
    int		si_protocol;		/* cosign protocol version */
    char	si_ipaddr[ 256 ];	/* longer than need be */
    char	si_user[ 130 ];		/* 64@64\0 */
    char	si_realm[ 256 ];	/* longer than need be */
    char	si_factor[ 256 ];	/* longer than need be? */
#ifdef KRB
    char	si_krb5tkt[ MAXPATHLEN ];
#endif /* KRB */
    time_t	si_itime;
};

int read_scookie( char *, struct sinfo *, void * );

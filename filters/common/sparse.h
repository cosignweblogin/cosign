struct sinfo {
    char	si_ipaddr[ 256 ];	/* longer than need be */
    char	si_user[ 130 ];		/* 64@64\0 */
    char	si_realm[ 256 ];	/* longer than need be */
#ifdef KRB
    char	si_krb5tkt[ MAXPATHLEN ];
#ifdef KRB4
    char	si_krb4tkt[ MAXPATHLEN ];
#endif /* KRB */
#endif /* KRB4 */
    time_t	si_itime;
};

int read_scookie( char *, struct sinfo *, server_rec * );

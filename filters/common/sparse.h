struct sinfo {
    char	si_ipaddr[ 256 ];
    char	si_user[ 32 ];
    char	si_realm[ 256 ];
    time_t	si_itime;
};

#define SECANT_NOT_IN_FS 	-1
#define SECANT_OK		0

int read_a_secant( char *, struct sinfo * );

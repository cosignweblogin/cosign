#define NOTAUTH 0 
#define CGI	1
#define SERVICE	2
#define DAEMON	3

#define CH_TICKET	(1<<0)
#define CH_PROXY	(1<<1)

struct chosts {
    char		*ch_hostname;
    int			ch_key;
    int			ch_flag;
    struct proxies	*ch_proxies;
    struct chosts	*ch_next;
};

struct proxies {
    char		*pr_hostname;
    char		*pr_cookie;
    struct proxies	*pr_next;
};

struct cosigncfg {
    char 		*cc_key;
    char 		**cc_value;
    unsigned int 	cc_numval;
    struct cosigncfg 	*cc_next;
};

#define COSIGNDBKEY		"cosigndb"
#define COSIGNCADIRKEY		"cosigncadir"
#define COSIGNCERTKEY		"cosigncert"
#define	COSIGNKEYKEY		"cosignkey"
#define COSIGNHOSTKEY		"cosignhost"
#define COSIGNTICKKEY		"cosignticketcache"
#define COSIGNHOSTKEY		"cosignhost"
#define COSIGNKEYTABKEY		"cosignkeytab"
#define	COSIGNLOGOUTURLKEY	"cosignlogouturl"

#ifdef SQL_FRIEND
#define MYSQLDBKEY	"mysqldb"
#define MYSQLUSERKEY	"mysqluser"
#define MYSQLPASSWDKEY	"mysqlpasswd"
#endif

struct chosts * chosts_find( char *host );
int parseConfig( char *path );
char * getConfigValue( char *key );
char ** getAllConfigValues( char *key, int *nVals );

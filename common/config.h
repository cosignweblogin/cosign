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


struct chosts * chosts_find( char * );
int chosts_read( char * );
int proxy_read( struct chosts *, char * );

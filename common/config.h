#define NOTAUTH 0 
#define CGI	1
#define SERVICE	2
#define DAEMON	3

struct chosts {
    char		*ch_hostname;
    int			ch_key;
    int			ch_tkt;
    struct chosts	*ch_next;
};


struct chosts * chosts_find( char * );
int chosts_read( char * );

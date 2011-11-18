/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */
#include <regex.h>	/* needed for regmatch parameters below. */

#define NOTAUTH 0 
#define CGI	1
#define SERVICE	2
#define DAEMON	3

#define SL_TICKET	(1<<0)
#define SL_REAUTH	(1<<1)
#define SL_SCHEME_V2	(1<<2)

#define AL_PROXY	(1<<0)

#define COSIGN_HANDLER_PATH	"/cosign/valid"

#define COSIGN_MAXFACTORS	5
struct servicelist {
    char		*sl_cookie;
    char		*sl_cookiesub;
    char		*sl_wkurl;
    int			sl_flag;
    char		*sl_factors[ COSIGN_MAXFACTORS ];
    struct authlist	*sl_auth;
    struct servicelist	*sl_next;
};

struct authlist {
    char		*al_hostname;
    int			al_key;
    int			al_flag;
    struct proxies	*al_proxies;
    struct authlist	*al_next;
};

#define FL_MAXFORMFIELDS	6
struct factorlist {
    char		*fl_path;
    int			fl_flag;
    char		*fl_formfield[ FL_MAXFORMFIELDS ];
    struct factorlist	*fl_next;
};

struct proxies {
    char		*pr_hostname;
    char		*pr_cookie;
    struct proxies	*pr_next;
};

struct matchlist {
    char                *ml_key;
    char                *ml_regexp;
    char                *ml_login;
    char                *ml_realm;
    struct matchlist    *ml_next;
};

#define COSIGNDBKEY		"cosigndb"
#define COSIGNCADIRKEY		"cosigncadir"
#define COSIGNCERTKEY		"cosigncert"
#define	COSIGNKEYKEY		"cosignkey"
#define COSIGNTICKKEY		"cosignticketcache"
#define COSIGNDTICKKEY		"cosigndticketcache"
#define COSIGNTMPLDIRKEY	"cosigntmpldir"
#define COSIGNHOSTKEY		"cosignhost"
#define COSIGNKEYTABKEY		"cosignkeytab"
#define COSIGNPRINCIPALKEY	"cosignprincipal"
#define COSIGNSTORETICKETSKEY	"cosignstoretickets"
#define COSIGNTICKETLIFETIMEKEY	"cosignticketlifetime"
#define	COSIGNLOGOUTURLKEY	"cosignlogouturl"
#define	COSIGNLOGOUTREGEXKEY	"cosignlogoutregex"
#define COSIGNTIMEOUTKEY	"cosignnettimeout"
#define COSIGNPORTKEY		"cosignport"
#define COSIGNLOOPURLKEY	"cosignloopurl"
#define COSIGNX509TKTSKEY       "cosignx509krbtkts"
#define COSIGNKRBTKTSKEY	"cosignkrbtkts"
#define COSIGNDBHASHLENKEY	"cosigndbhashlen"
#define COSIGNSTRICTCHECKKEY	"cosignstrictcheck"
#define COSIGNHTTPONLYCOOKIESKEY	"cosignhttponlycookies"

#ifdef SQL_FRIEND
#define MYSQLDBKEY	"mysqldb"
#define MYSQLUSERKEY	"mysqluser"
#define MYSQLPASSWDKEY	"mysqlpasswd"
#endif

int		cosign_ssl( char *, char *, char *, SSL_CTX ** );
struct authlist	*authlist_find( char * );
struct servicelist	*service_find( char *, regmatch_t [], int );
int		cosign_config( char * );
char		*cosign_config_get( char * );
char		**cosign_config_get_all( char *, int * );
int		match_substitute( char *, int, char *, int,
			regmatch_t [], char * );
int		matchlist_process( struct matchlist *, char *,
			char **, char ** );
int 		x509_translate( char *, char *, char **, char ** );
int		negotiate_translate( char *, char **, char ** );
int		pick_authenticator( char *,char **, char **, char **,
			struct matchlist ** );


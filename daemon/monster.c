/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <dirent.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <snet.h>

#include "cparse.h"
#include "mkcookie.h"
#include "logname.h"
#include "rate.h"
#include "monster.h"
#include "conf.h"

/* idle_cache = (grey+idle) from cosignd, plus loggedout_cache here */
int		idle_cache = (60 * 30) +  (60 * 60 * 2) + (60 * 60 * 2);
int		interval = 60 * 2;
int		hard_timeout = 60 * 60 * 12;
int		loggedout_cache = 60 * 60 * 2;
int             debug = 0;
int		login_gone;
int		hashlen = 0;
extern char	*cosign_version;

int		login_total, login_sent, service_total, service_gone;

static void (*logger)( char * ) = NULL;

static int eat_cookie( char *, struct timeval *, time_t *, int * );
static void do_dir( char *, struct connlist *, struct timeval * );

char    	*cosign_dir = _COSIGN_DIR;
char		*cryptofile = _COSIGN_TLS_KEY;
char		*certfile = _COSIGN_TLS_CERT;
char		*cadir = _COSIGN_TLS_CADIR;
struct timeval	cosign_net_timeout = { 60 * 4, 0 };
unsigned short	cosign_port;

    static void
monster_configure()
{
    char	 *val;

    if (( val = cosign_config_get( COSIGNDBKEY )) != NULL ) {
	cosign_dir = val;
    }

    if (( val = cosign_config_get( COSIGNCADIRKEY )) != NULL ) {
	cadir = val;
    }

    if (( val = cosign_config_get( COSIGNCERTKEY )) != NULL ) {
	certfile = val;
    }

    if (( val = cosign_config_get( COSIGNKEYKEY )) != NULL ) {
	cryptofile = val;
    }

    if (( val = cosign_config_get( COSIGNTIMEOUTKEY )) != NULL ) {
	cosign_net_timeout.tv_sec = atoi( val );
	cosign_net_timeout.tv_usec = 0;
    }

    if (( val = cosign_config_get( COSIGNPORTKEY )) != NULL ) {
	cosign_port = htons( atoi( val ));
    } else {
	cosign_port = htons( 6663 );
    }

    if (( val = cosign_config_get( COSIGNDBHASHLENKEY )) != NULL ) {
	hashlen = atoi( val );
    }
}


    int
main( int ac, char **av )
{
    struct timeval	tv, now;
    struct hostent	*he;
    struct connlist	*head = NULL,*new = NULL, *temp, *yacur = NULL;
    struct connlist	**tail = NULL, **cur;
    char		hostname[ MAXHOSTNAMELEN ];
    char		hashdir[ 3 ];
    char		*sixtyfourchars = "abcdefghijklmnopqrstuvwxyz"
    					"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"0123456789+-";
    char		*prog, *line;
    int			c, i, err = 0;
    char           	*cosign_host = NULL;
    char		*cosign_conf = _COSIGN_CONF;
    char		*p, *q;
    int                 facility = _COSIGN_LOG, level = LOG_INFO;
    int			fg = 0;
    SSL_CTX		*m_ctx = NULL;
    extern int          optind;
    extern char         *optarg;

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }


#define MONSTER_OPTS "c:dF:fh:H:i:I:l:L:p:Vx:y:z:"
    while (( c = getopt( ac, av, MONSTER_OPTS )) != EOF ) {
	switch ( c ) {
	case 'c':
	    cosign_conf = optarg;
	    break;

        default:
            break;
	}
    }

    if ( cosign_config( cosign_conf ) < 0 ) {
	fprintf( stderr, "monster: cosign_config failed.\n" );
	exit( 1 );
    }
    monster_configure();

    /* reset optind to parse all other args */
    optind = 1;

    while (( c = getopt( ac, av, MONSTER_OPTS )) != EOF ) {
	switch ( c ) {
	case 'c':
	    break;

	case 'd' :		/* debug */
	    debug++;
	    break;

	case 'F' :              /* syslog facility */
	    if (( facility = syslogfacility( optarg )) == -1 ) {
		fprintf( stderr, "%s: %s: unknown syslog facility\n",
			prog, optarg );
		exit( 1 );
	    }
	    break;

	case 'f' :		/* run in foreground */
	    fg = 1;
	    break;

	case 'h' :		/* host running cosignd */
	    cosign_host = optarg;
	    break;

	case 'H' :		/* hard timeout for all cookies */
	    hard_timeout = atoi( optarg );
	    break;

	case 'i' :              /* idle timeout in seconds*/
	    idle_cache = atoi( optarg );
	    break;

	case 'I' :              /* timestamp pushing interval*/
	    interval = atoi( optarg );
	    break;

	case 'l' :              /* how long to keep logged out cookies*/
	    loggedout_cache = atoi( optarg );
	    break;

	case 'L' :              /* syslog level */
	    if (( level = sysloglevel( optarg )) == -1 ) {
		fprintf( stderr, "%s: %s: unknown syslog level\n",
			prog, optarg );
		exit( 1 );
	    }
	    break;

	case 'p' :              /* TCP port */
	     cosign_port = htons( atoi( optarg ));
	     break;

	case 'V' :              /* version */
	    printf( "%s\n", cosign_version );
	    exit( 0 );

	case 'x' :		/* ca dir */
	    cadir = optarg;
	    break;
	
	case 'y' :		/* cert */
	    certfile = optarg;
	    break;
	
	case 'z' :		/* private key file */
	    cryptofile = optarg;
	    break;
	
	case '?':
            err++;
            break;

        default:
            err++;
            break;
	}
    }

    if ( err || optind != ac ) {
	fprintf( stderr, "Usage: monster [ -c conf ] [ -dV ] " );
	fprintf( stderr, "[ -F syslog-facility ] [ -h cosignd-host ] ");
	fprintf( stderr, "[ -H hard-timeout  ] [ -i idlecachetimeinsecs ] " );
	fprintf( stderr, "[ -I update-interval ] [ -l loggedoutcachetime ]  " );
	fprintf( stderr, "[ -L syslog-level] [ -p port ] [ -x ca-dir ] " );
	fprintf( stderr, "[ -y cert-file] [ -z private-key-file ]\n" );
	exit( -1 );
    }

    if ( cosign_host != NULL ) {
	if ( gethostname( hostname, sizeof( hostname )) < 0 ) {
	    perror( "gethostname" );
	    exit( 1 );
	}

	if (( he = gethostbyname( cosign_host )) == NULL ) {
	    fprintf( stderr, "host unknown: %s\n", cosign_host );
	    exit( 1 );
	}
	tail = &head;
	for ( i = 0; he->h_addr_list[ i ] != NULL; i++ ) {
	    if (( new = ( struct connlist * )
		    malloc( sizeof( struct connlist ))) == NULL ) {
		perror( "connlist build" );
		exit( 1 );
	    }

	    memset( &new->cl_sin, 0, sizeof( struct sockaddr_in ));
	    new->cl_sin.sin_family = AF_INET;
	    new->cl_sin.sin_port = cosign_port;
	    memcpy( &new->cl_sin.sin_addr.s_addr,
		    he->h_addr_list[ i ], (unsigned int)he->h_length );
	    new->cl_sn = NULL;
	    new->cl_last_time = 0;
	    *tail = new;
	    tail = &new->cl_next;
	}
	*tail = NULL;

	SSL_load_error_strings();
	SSL_library_init();

	if ( cosign_ssl( cryptofile, certfile, cadir, &m_ctx ) != 0 ) {
	    fprintf( stderr, "monster: ssl setup error\n" );
	    exit( 1 );
	}
    }

    if ( chdir( cosign_dir ) < 0 ) {
	perror( cosign_dir );
	exit( 1 );
    }

    /* Disassociate from controlling tty. */

    if ( !fg && !debug ) {
	int		i, fd, dt;

	switch ( fork()) {
	case 0 :
	    if ( setsid() < 0 ) {
		perror( "setsid" );
		exit( 1 );
	    }
	    if (( fd = open( "/", O_RDONLY, 0 )) < 0 ) {
		perror( "open" );
		exit( 1 );
	    }
	    dt = getdtablesize();
	    for ( i = 0; i < dt; i++ ) {
		if ( i != fd ) {			
		    (void)close( i );
		}
	    }
	    (void)dup2( fd, 0 );
	    (void)dup2( fd, 1 );
	    (void)dup2( fd, 2 );

	    (void)close( fd );
	    break;

	case -1 :
	    perror( "fork" );
	    exit( 1 );
	default :
	    exit( 0 );
	}
    }

    /*
     * Start logging.
     */
    openlog( prog, LOG_NDELAY|LOG_NOWAIT|LOG_PID, facility );
    setlogmask( LOG_UPTO( level ));

    syslog( LOG_INFO, "restart %s", cosign_version );

	for (;;) {

    sleep( interval );
    login_total = service_total = login_gone = service_gone = login_sent = 0;

    if ( gettimeofday( &now, NULL ) != 0 ){
	syslog( LOG_ERR, "gettimeofday: %m" );
	exit( -1 );
    }

    /*
     * Usually, we'd write this as a nice neat for loop.  In this case,
     * since we have the ugly combination of a traversal and a possible
     * deletion, we use a while loop so we can better control the increment.
     */
    cur = &head;
    while ( *cur != NULL ) {
	if ( (*cur)->cl_sn == NULL ) {
	    if ( connect_sn( *cur, m_ctx, cosign_host, 1 ) != 0 ) {
		goto next;
	    }

	    snet_writef( (*cur)->cl_sn, "DAEMON %s\r\n", hostname );

	    tv = cosign_net_timeout;
	    if (( line = snet_getline_multi( (*cur)->cl_sn, logger, &tv ))
		    == NULL ) {
		syslog( LOG_ERR, "snet_getline_multi: 1: %m" );
		if (( snet_close( (*cur)->cl_sn )) != 0 ) {
		    syslog( LOG_ERR, "monster: snet_close: 2: %m" );
		}
		goto next;
	    }

	    if ( *line == '4' ) {
		if (( close_sn( *cur )) != 0 ) {
		    syslog( LOG_ERR, "close_sn: 3: %m" );
		}
		temp = *cur;
		*cur = (*cur)->cl_next;
		free( temp );
		/*
		 * we don't need to increment the loop in this case
		 * because the delete implicitly does.
		 */
		continue;

	    } else if ( *line != '2' ) {
		syslog( LOG_ERR, "getline: 4: %s", line );
		if (( close_sn( *cur )) != 0 ) {
		    syslog( LOG_ERR, "close_sn: 5: %m" );
		}
		goto next;
	    }
	}

	if ( snet_writef( (*cur)->cl_sn, "TIME\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "snet_writef failed on TIME");
	    if ( snet_close( (*cur)->cl_sn ) != 0 ) {
		syslog( LOG_ERR, "snet_close: 6: %m" );
	    }
	    goto next;
	}

	tv = cosign_net_timeout;
	if (( line = snet_getline_multi( (*cur)->cl_sn, logger, &tv ))
		== NULL ) {
	    if ( !snet_eof( (*cur)->cl_sn )) {
		syslog( LOG_ERR, "snet_getline_multi: 7: %m" );
	    }
	    if ( snet_close( (*cur)->cl_sn ) != 0 ) {
		syslog( LOG_ERR, "snet_close: 8: %m" );
	    }
	    goto next;
	}

	if ( *line != '3' ) {
	    syslog( LOG_ERR, "snet_getline_multi: 9: %s", line );
	    if ( snet_close( (*cur)->cl_sn ) != 0 ) {
		syslog( LOG_ERR, "snet_close: 10: %m" );
	    }
next:
	    (*cur)->cl_sn = NULL;
	}
	cur = &(*cur)->cl_next;
    }

    switch ( hashlen ) {
    case 0 :
	do_dir( ".", head, &now );
	break;
    
    case 1 :
	for ( p = sixtyfourchars; *p != '\0'; p++ ) {
	    hashdir[ 0 ] = *p;
	    hashdir[ 1 ] = '\0';
	    do_dir( hashdir, head, &now );
	}
	break;

    case 2 :
	for ( p = sixtyfourchars; *p != '\0'; p++ ) {
	    for ( q = sixtyfourchars; *q != '\0'; q++ ) {
		hashdir[ 0 ] = *p;
		hashdir[ 1 ] = *q;
		hashdir[ 2 ] = '\0';
		do_dir( hashdir, head, &now );
	    }
	}
	break;

    default :
	syslog( LOG_ERR, "Illegal hashlen %d", hashlen );
	exit( 1 );
    }

    for ( yacur = head; yacur != NULL; yacur = yacur->cl_next ) {
	if ( yacur->cl_sn != NULL ) {
	    snet_writef( yacur->cl_sn, ".\r\n" );
	    if (( line = snet_getline_multi( yacur->cl_sn, logger, &tv ))
		     == NULL ) {
		if ( !snet_eof( yacur->cl_sn )) {
		    syslog( LOG_ERR, "snet_getline_multi: 13: %m" );
		}
		if ( snet_close( yacur->cl_sn ) != 0 ) {
		    syslog( LOG_ERR, "snet_close: 14: %m" );
		}
		yacur->cl_sn = NULL;
		continue;
	    }
	    if ( *line != '2' ) {
		syslog( LOG_ERR, "snet_getline_multi: 15: %m" );
		if ( snet_close( yacur->cl_sn ) != 0 ) {
		    syslog( LOG_ERR, "snet_close: 16: %m" );
		}
		yacur->cl_sn = NULL;
		continue;
	    }
	    yacur->cl_last_time = now.tv_sec;
	}

    }
    syslog( LOG_NOTICE, "STATS MONSTER: %d/%d/%d login %d/%d service",
	    login_gone, login_sent, login_total, service_gone, service_total );
	} /* end forever loop */
}

    void
do_dir( char *dir, struct connlist *head, struct timeval *now )
{
    DIR			*dirp;
    struct dirent	*de;
    char		path[ MAXPATHLEN ];
    char		lpath[ MAXPATHLEN ];
    struct connlist	*yacur;
    char                login[ MAXCOOKIELEN ];
    int			state = 0;
    time_t		itime = 0;
    int			rc;

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "%s: %m", cosign_dir);
	exit( 1 );
    }
    while (( de = readdir( dirp )) != NULL ) {
	/* is a login cookie */

	if ( mkcookiepath( NULL, hashlen, de->d_name,
		path, sizeof( path )) < 0 ) {
	    continue;
	}

	if ( strncmp( de->d_name, "cosign=", 7 ) == 0 ) {
	    login_total++;

	    if (( rc = eat_cookie( path, now, &itime, &state )) < 0 ) {
		syslog( LOG_ERR, "eat_cookie failure: %s", path );
		continue;
	    }
	    for ( yacur = head; yacur != NULL; yacur = yacur->cl_next ) {
		if (( itime > yacur->cl_last_time ) &&
			( yacur->cl_sn != NULL )) {
		    login_sent++;
		    if ( snet_writef( yacur->cl_sn, "%s %d %d\r\n",
			    de->d_name, itime, state ) < 0 ) {
			if ( snet_close( yacur->cl_sn ) != 0 ) {
			    syslog( LOG_ERR, "snet_close: 11: %m" );
			}
			yacur->cl_sn = NULL;
			continue;
		    }
		}
	    }
	} else if ( strncmp( de->d_name, "cosign-", 7 ) == 0 ) {
	    service_total++;
	    if ( service_to_login( path, login ) != 0 ) {
		continue;
	    }

	    if ( mkcookiepath( NULL, hashlen, login,
		    lpath, sizeof( lpath )) < 0 ) {
		syslog( LOG_ERR, "do_dir: mkcookiepath error." );
		exit( 1 );
	    }

	    if (( rc = eat_cookie( lpath, now, &itime, &state )) < 0 ) {
		syslog( LOG_ERR, "eat_cookie failure: %s", login );
		continue;
	    }
	    if ( rc == 0 ) {
		if ( unlink( path ) != 0 ) {
		    syslog( LOG_ERR, "%s: 12: %m", path );
		}
		service_gone++;
	    }
	} else {
	    continue;
	}
    }
    closedir( dirp );
}

    int
eat_cookie( char *name, struct timeval *now, time_t *itime, int *state )
{
    struct cinfo	ci;
    int			rc, create = 0;
    extern int		errno;


    /* -1 is a serious error
     * 0 means the cookie was deleted
     * 1 means still good and time was updated
     */

    if (( rc = read_cookie( name, &ci )) < 0 ) {
	syslog( LOG_ERR, "read_cookie error: %s", name );
	return( -1 );
    }

    /* login cookie gave us an ENOENT so we think it's gone */
    if ( rc == 1 ) {
	return( 0 );
    }

    /* logged out plus extra non-fail overtime */
    if ( !ci.ci_state && (( now->tv_sec - ci.ci_itime ) > loggedout_cache )) {
	goto delete_stuff;
    }

    /* idle out, plus gray window, plus non-failover */
    if (( now->tv_sec - ci.ci_itime )  > idle_cache ) {
	goto delete_stuff;
    }

    /* hard timeout */
    create = atoi( ci.ci_ctime );
    if (( now->tv_sec - create )  > hard_timeout ) {
	goto delete_stuff;
    }

    *itime = ci.ci_itime; 
    *state = ci.ci_state;
    return( 1 );

delete_stuff:

    /* remove krb5 ticket and login cookie */
    if ( *ci.ci_krbtkt != '\0' ) {
	if ( unlink( ci.ci_krbtkt ) != 0 ) {
	    syslog( LOG_ERR, "unlink krbtgt %s: %m", ci.ci_krbtkt );
	}
    }
    if ( unlink( name ) != 0 ) {
	syslog( LOG_ERR, "%s: %m", name );
    } 
    login_gone++;

    return( 0 );
}

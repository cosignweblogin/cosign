#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

#include "cparse.h"

/* 90 minutes */
int	idle = 45000;

int decision( char *, struct timeval * );

    int
main( int ac, char **av )
{
    DIR			*dirp;
    struct dirent	*de;
    struct timeval	tv;
    char                login[ MAXPATHLEN ];
    int			c, err= 0;
    int			rc;
    char           	*cosign_dir = _COSIGN_DIR;
    extern int          optind, errno;
    extern char         *optarg;

    while (( c = getopt( ac, av, "i:" )) != EOF ) {
	switch ( c ) {
	case 'i' :              /* idle timeout in seconds*/
	    idle = atoi(optarg);
	    break;

	case '?':
            err++;
            break;

        default:
            err++;
            break;

        }
    }

    if ( err ) {
        fprintf( stderr, "usage: monster [ -i idletimeinseconds ] ...\n" );
        exit( -2 );
    }

    if ( chdir( cosign_dir ) < 0 ) {
	perror( cosign_dir );
	exit( 1 );
    }

    if (( dirp = opendir( cosign_dir )) == NULL ) {
	perror( cosign_dir );
	exit( -1 );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ){
	fprintf( stderr, "gettimeofday failed!\n" );
	exit( -1 );
    }
    while (( de = readdir( dirp )) != NULL ) {
	/* is a login cookie */
	if ( strncmp( de->d_name, "cosign=", 7 ) == 0 ) {
	    if ( decision( de->d_name, &tv ) < 0 ) {
		fprintf( stderr, "decision failure: %s\n", de->d_name );
		continue;
	    }

	} else if ( strncmp( de->d_name, "cosign-", 7 ) == 0 ) {

	    if ( service_to_login( de->d_name, login ) != 0 ) {
		fprintf( stderr, "service to login: %s\n", de->d_name );
		continue;
	    }
	    if (( rc = decision( login, &tv )) < 0 ) {
		fprintf( stderr, "decision failure: %s\n", login );
		continue;
	    }
	    if ( rc  == 0 ) {
		fprintf( stderr, "deleteing: %s\n", de->d_name );
		if ( unlink( de->d_name ) != 0 ) {
		    fprintf( stderr, "%s: %s\n", de->d_name, strerror( errno ));
		}
	    }
	} else {
	    continue;
	}
    }
    closedir( dirp );
    exit( 0 );
}

    int
decision( char *name, struct timeval *tv )
{
    struct cinfo	ci = { 0, 0, "\0","\0","\0", "\0","\0", 0, };
    int			rc;
    extern int		errno;


    if (( rc = read_cookie( name, &ci )) < 0 ) {
	fprintf( stderr, "read_cookie error: %s\n", name );
	return( -1 );
    }

    /* login cookie gave us an ENOENT do we think it's gone */
    if ( rc == 1 ) {
	fprintf( stderr, "%s already gone\n", name );
	return( 0 );
    }

    if ( !ci.ci_state ) {
	fprintf( stderr, "%s logged out\n", name );
	goto delete_stuff;
    }

    if ( tv->tv_sec - ci.ci_itime  > idle ) {
	fprintf( stderr, "%s idle out\n", name );
	goto delete_stuff;
    }

    fprintf( stderr, "leaving %s alone\n", name );
    return( 1 );

delete_stuff:

    /* clean up ticket and file */
    if ( strcmp( ci.ci_krbtkt, "\0" ) != 0 ) {
	fprintf( stderr, "deleteing: %s\n", ci.ci_krbtkt );
	if ( unlink( ci.ci_krbtkt ) != 0 ) {
	    fprintf( stderr, "%s: %s\n", ci.ci_krbtkt, strerror( errno ));
	}
    }
    fprintf( stderr, "deleteing: %s\n", name );
    if ( unlink( name ) != 0 ) {
	fprintf( stderr, "%s: %s\n",name, strerror( errno ));
    }

    return( 0 );
}

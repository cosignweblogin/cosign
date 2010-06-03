//#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COSIGN_CGI_OK                 0
#define COSIGN_CGI_ERROR              1
#define COSIGN_CGI_PASSWORD_EXPIRED   2

#define HAVE_LIBPAM			1
#define HAVE_SECURITY_PAM_APPL_H	1

#ifdef HAVE_LIBPAM
    #ifdef HAVE_PAM_PAM_APPL_H
	#include <pam/pam_appl.h>
    #elif HAVE_SECURITY_PAM_APPL_H
	#include <security/pam_appl.h>
    #else /* !HAVE_PAM_ */
	#error Cannot find pam_appl.h
    #endif /* HAVE_PAM_ */
#endif /* HAVE_LIBPAM */

#define FACTOR_MAX_INPUT	256	

extern int		errno;

    static int
factor_conv( int num_msg, struct pam_message **msg,
		struct pam_response **resp, void *appdata_ptr )
{
    struct pam_response		*presp = NULL;
    char			*passcode;
    char			*data;
    int				i;

    if ( num_msg <= 0 ) {
	return( PAM_CONV_ERR );
    }

    /* see pam_start(3). app allocates, modules free. */
    if (( presp = (struct pam_response *)malloc( num_msg *
			sizeof( struct pam_response ))) == NULL ) {
	return( PAM_CONV_ERR );
    }

    passcode = (char *)appdata_ptr;

    for ( i = 0; i < num_msg; i++ ) {
	switch( msg[ i ]->msg_style ) {
	case PAM_PROMPT_ECHO_ON:
	case PAM_PROMPT_ECHO_OFF:
	    if (( data = strdup( passcode )) == NULL ) {
		goto factor_conv_failed;
	    }
	    break;

	case PAM_TEXT_INFO:
	case PAM_ERROR_MSG:
	    data = NULL;
	    break;

	default:
	    goto factor_conv_failed;
	}

	/* see pam_conv(3). resp_retcode is unused & should be set to zero. */
	presp[ i ].resp = data;
	presp[ i ].resp_retcode = 0;
	data = NULL;
    }

    *resp = presp;
    presp = NULL;

    return( PAM_SUCCESS );

factor_conv_failed:
    if ( presp != NULL ) {
	for ( i = 0; i < num_msg; i++ ) {
	    if ( presp[ i ].resp != NULL ) {
		free( presp[ i ].resp );
		presp[ i ].resp = NULL;
	    }
	    free( presp );
	    presp = NULL;
	}
    }

    return( PAM_CONV_ERR );
}

    int
main( int ac, char *av[] )
{
    pam_handle_t	*ph;
    struct pam_conv	pconv;
    char		*factor_name = NULL;
    char		login[ FACTOR_MAX_INPUT ];
    char		passcode[ FACTOR_MAX_INPUT ];
    int			len;
    int			rc;

    if (( factor_name = strrchr( av[ 0 ], '/' )) == NULL ) {
	factor_name = av[ 0 ];
    } else {
	factor_name++;
    }

    if ( fgets( login, sizeof( login ), stdin ) == NULL ) {
	printf( "Internal error: login missing.\n" );
	fprintf( stderr, "[%s] [-] Internal error: login missing\n",
		factor_name );
	exit( COSIGN_CGI_ERROR );
    }
    len = strlen( login );
    if ( login[ len - 1 ] != '\n' ) {
	printf( "Internal error: login too long.\n" );
	fprintf( stderr, "[%s] [%s] Internal error: login too long\n",
		factor_name, login );
	exit( COSIGN_CGI_ERROR );
    }
    login[ len - 1 ] = '\0';

    if ( fgets( passcode, sizeof( passcode ), stdin ) == NULL ) {
	printf( "Internal error: passcode missing.\n" );
	fprintf( stderr, "[%s] [%s] Internal error: passcode missing\n",
		factor_name, login );
	exit( COSIGN_CGI_ERROR );
    }
    len = strlen( passcode );
    if ( passcode[ len - 1 ] != '\n' ) {
	printf( "Internal error: passcode too long.\n" );
	fprintf( stderr, "[%s] [%s] Internal error: passcode too long\n",
		factor_name, login );
	exit( COSIGN_CGI_ERROR );
    }
    passcode[ len - 1 ] = '\0';

    pconv.conv = (int (*)())factor_conv;
    pconv.appdata_ptr = passcode;

    if (( rc = pam_start( factor_name, login, &pconv, &ph )) != PAM_SUCCESS ) {
	printf( "Internal error: %s\n", pam_strerror( ph, rc ));
	fprintf( stderr, "[%s] [%s] Internal error: pam_start failed: %s\n",
		factor_name, login, pam_strerror( ph, rc ));
	exit( COSIGN_CGI_ERROR );
    }

    if (( rc = pam_authenticate( ph, PAM_SILENT )) != PAM_SUCCESS ) {
	printf( "Internal error: %s\n", pam_strerror( ph, rc ));
	fprintf( stderr, "[%s] [%s] Internal error: pam_authenticate "
		"failed: %s\n", factor_name, login, pam_strerror( ph, rc ));
	exit( COSIGN_CGI_ERROR );
    }

    if (( rc = pam_acct_mgmt( ph, PAM_SILENT )) != PAM_SUCCESS ) {
	if ( rc == PAM_NEW_AUTHTOK_REQD ) {
	    printf( "Password expired.\n" );
	    fprintf( stderr, "[%s] [%s] Password expired\n",
			factor_name, login );
	    exit( COSIGN_CGI_PASSWORD_EXPIRED );
	}
	printf( "Internal error: %s\n", pam_strerror( ph, rc ));
	fprintf( stderr, "[%s] [%s] Internal error: pam_acct_mgmt "
		"failed: %s\n", factor_name, login, pam_strerror( ph, rc ));
	exit( COSIGN_CGI_ERROR );
    }

    if (( rc = pam_end( ph, rc )) != PAM_SUCCESS ) {
	printf( "Internal error: %s\n", pam_strerror( ph, rc ));
	fprintf( stderr, "[%s] [%s] Internal error: pam_end failed: %s\n",
		factor_name, login, pam_strerror( ph, rc ));
	exit( COSIGN_CGI_ERROR );
    }

    /* success */
    fprintf( stderr, "[%s] [%s] factor OK\n", factor_name, login );
    printf( "%s\n", factor_name );

    return( COSIGN_CGI_OK );
}

/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#define argcargv(X, Y) (acav_parse( NULL, X, Y ))

#define ACV_FLAG_DEFAULTS       0       
#define ACV_FLAG_BACKSLASH      (1 << 0)
#define ACV_FLAG_QUOTE          (1 << 1)

#define acav_flag_defaults( x )         (x)->acv_flags = ACV_FLAG_DEFAULTS
#define acav_flag_set( x, y )           (x)->acv_flags |= (y)
#define acav_flag_unset( x, y )         (x)->acv_flags &= ~(y)

typedef struct {
    int		acv_argc;
    char	**acv_argv;
    int		acv_flags;
} ACAV;
ACAV* acav_alloc( void );
int acav_parse( ACAV *acav, char *, char *** );
int acav_free( ACAV *acav );

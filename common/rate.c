/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include "rate.h"

    double
rate_tick( struct rate *r )
{
    long		seconds;
    struct timeval	tv;
    double		rate;

    if ( r->r_count == 0 ) {
	if ( gettimeofday( &r->r_tv, NULL ) < 0 ) {
	    return( (double)0 );
	}
	r->r_count = 1;
	return( (double)0 );
    }
    if (( ++r->r_count % RATE_INTERVAL ) == 0 ) {
	if ( gettimeofday( &tv, NULL ) < 0 ) {
	    return( (double)0 );
	}
	seconds = tv.tv_sec - r->r_tv.tv_sec;
	if ( tv.tv_usec <= r->r_tv.tv_usec ) {
	    r->r_tv.tv_usec -= 1000000;
	    seconds -= 1;
	}
	if (( tv.tv_usec - r->r_tv.tv_usec ) >= 500000 ) {
	    seconds += 1;
	}

	rate = (double)RATE_INTERVAL / tv.tv_sec;
	r->r_count = 1;
	r->r_tv = tv;
	return( rate );
    }
    return( (double)0 );
}

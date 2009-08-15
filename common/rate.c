/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include "rate.h"

    double
rate_get( struct rate *r )
{
    long		seconds;

    if (r->r_count <= 1 ) {
	return( (double)0 );
    }

    seconds = r->r_tv_last.tv_sec - r->r_tv.tv_sec;
    if ( r->r_tv_last.tv_usec <= r->r_tv.tv_usec ) {
	r->r_tv.tv_usec -= 1000000;
	seconds -= 1;
    }
    if (( r->r_tv_last.tv_usec - r->r_tv.tv_usec ) >= 500000 ) {
	seconds += 1;
    }

    /*
     * if the rate is > 100 / sec, we don't log anything?
     * should allow fractions of a second.
     */
    if ( seconds <= 0 ) {
	return( (double)0 );
    }
    return( (double)(r->r_count - 1) / seconds );
}

    double
rate_tick( struct rate *r )
{
    double		rate;

    if ( r->r_count == 0 ) {
	if ( gettimeofday( &r->r_tv, NULL ) < 0 ) {
	    return( (double)0 );
	}
	r->r_count = 1;
	return( (double)0 );
    }
    if ( gettimeofday( &r->r_tv_last, NULL ) < 0 ) {
	return( (double)0 );
    }
    if (( ++r->r_count % RATE_INTERVAL ) == 0 ) {
	rate = rate_get( r );
	r->r_count = 1;
	r->r_tv = r->r_tv_last;
	return( rate );
    }
    return( (double)0 );
}

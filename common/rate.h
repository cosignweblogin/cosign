/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

struct rate {
    int			r_count;
    struct timeval	r_tv;
};

#define RATE_INTERVAL	100	

double rate_tick( struct rate * );


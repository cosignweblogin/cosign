/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <snet.h>

#include "cosign.h"

    int
cookie_valid( struct sinlist *s_cur, char *cookie )
{
   if (( copy_connections( s_cur )) != 0 ) {
       return( 1 );
   }
   return( 0 );
}

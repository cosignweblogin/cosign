#include "config.h"

#include <stdlib.h>
#include <stdio.h>

#include "uservar.h"

    struct uservarlist *
uservar_new( )
{
  struct uservarlist *newp = ( struct uservarlist *) malloc ( sizeof ( struct uservarlist ) );
  if ( newp == NULL ) {
    return NULL;
  }

  newp->uv_var = NULL;
  newp->uv_value = NULL;
  newp->uv_next = NULL;

  return newp;
}

    void
uservar_dispose( struct uservarlist *l )
{
  while ( l ) {
    struct uservarlist *p = l;

    if ( l->uv_var ) {
      free( l->uv_var );
    }
    if ( l->uv_value ) {
      free ( l->uv_value );
    }

    l = l->uv_next;
    free( p );
  }
}

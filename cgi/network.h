/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */
int cosign_login( struct connlist *, char *, char *, char *, char *, char * );
int cosign_logout( struct connlist *, char *, char * );
int cosign_register( struct connlist *, char *, char *, char * );
int cosign_check( struct connlist *, char * );
int connect_sn( struct connlist *, char * );
int close_sn( struct connlist * );

/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

SNET * connectsn( char *host, int port );
int closesn( SNET *sn );
int cosign_login( char *, char *, char *, char *, char * );
int cosign_logout( char *, char * );
int cosign_register( char *, char *, char * );
int cosign_check( char * );

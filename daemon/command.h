/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See LICENSE.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

extern int	tlsopt;

int		command ___P(( int, SNET * ));
int		argcargv ___P(( char *, char **[] ));

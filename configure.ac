# Process this file with autoconf to produce a configure script.
AC_INIT(cosign,VERSION,cosign@umich.edu) 
AC_PREREQ(2.53)
AC_COPYRIGHT([Copyright (c) 2001-2002 Regents of The University of Michigan.  All Rig
hts Reserved.])
AC_CONFIG_SRCDIR([version.c])
#AC_CONFIG_HEADER([config.h])

AC_PATH_PROG(apxspath, apxs)
AC_PATH_PROG(apachectlpath, apachectl)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LEX
AC_PROG_YACC

# Checks for libraries.
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])

CHECK_SSL
CHECK_LIBKRB
CHECK_APACHE

# Checks for header files.
#AC_HEADER_STDC
#AC_HEADER_SYS_WAIT
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
#AC_C_CONST
#AC_HEADER_TIME

# Checks for library functions.
#AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_UTIME_NULL
#AC_CHECK_FUNCS([bzero dup2 gethostbyaddr gethostbyname gettimeofday inet_ntoa isascii memset select socket strcasecmp strchr strdup strerror strrchr strstr strtol utime])

AC_CONFIG_FILES([Makefile
                 cgi/Makefile
                 html/Makefile
                 daemon/Makefile
                 filters/apache/Makefile
                 libcgi/Makefile
                 libsnet/Makefile])
AC_OUTPUT

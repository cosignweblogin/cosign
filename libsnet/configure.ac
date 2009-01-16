# Process this file with autoconf to produce a configure script.
AC_INIT(libsnet,VERSION,rsug@umich.edu) 
AC_CONFIG_HEADER(config.h)
AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright (c) 1995-2003 Regents of The University of Michigan.  All Rights Reserved.])
AC_CONFIG_SRCDIR([snet.c])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL

AC_CANONICAL_SYSTEM

# Checks for libraries.
if test \! x_$with_ssl = x_no; then
    AC_CHECK_LIB([ssl], [SSL_accept], , [CHECK_SSL])
    AC_CHECK_LIB([crypto], [SSLeay_version], , [CHECK_SSL])
fi
CHECK_SASL
CHECK_UNIVERSAL_BINARIES

# Checks for header files.
#AC_HEADER_STDC
#AC_CHECK_HEADERS([fcntl.h inttypes.h netinet/in.h stdlib.h string.h sys/param.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
#AC_HEADER_TIME

# Checks for library functions.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_CHECK_FUNCS([gettimeofday select])

# Checks for how to build libraries
CHECK_PROFILED
AC_DISABLE_SHARED
AC_PROG_LIBTOOL  # Checks whether to build shared and/or static libraries

# Miscellaneous:
if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

# Write output:
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

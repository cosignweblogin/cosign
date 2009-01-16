AC_INIT(libcgi, VERSION, mprint@umich.edu)
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enables debug logging to standard out]), debug="-DEBUG", debug="" )
AC_SUBST(debug)

# Checks for programs.
AC_PROG_CC

AC_CANONICAL_HOST

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([memchr memmove strcasecmp strdup strerror strncasecmp strstr strtol])

CHECK_UNIVERSAL_BINARIES
AC_SUBST(OPTOPTS)

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

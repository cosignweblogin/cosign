# Process this file with autoconf to produce a configure script.
AC_INIT(cosign,VERSION,cosign@umich.edu) 
AC_PREREQ(2.53)
AC_COPYRIGHT([Copyright (c) 2001-2002 Regents of The University of Michigan.  All Rights Reserved.])
AC_CONFIG_SRCDIR([version.c])
#AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LEX
AC_PROG_YACC

AC_CANONICAL_HOST 

# Checks for libraries.
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([socket], [socket])

AC_ARG_ENABLE(krb, AC_HELP_STRING([--enable-krb=path_to_krb], [enable kerberos for the cgi and apache filter]), CHECK_LIBKRB, AC_MSG_RESULT( kerberos not enabled))
AC_ARG_WITH(krb4, AC_HELP_STRING([--with-krb4], [enable apache filter
to get Kerberos IV tickets]), CHECK_KRB4, AC_MSG_RESULT( kerberos IV not enabled))

AC_ARG_WITH(gss, AC_HELP_STRING([--with-gss], [enable apache filter
to set up GSSAPI ]), CHECK_GSS, AC_MSG_RESULT( GSSAPI not enabled))

AC_ARG_WITH(cosigndb, AC_HELP_STRING([--with-cosigndb=DIR], [default cosign database storage]), cosigndb="$withval", cosigndb="/var/cosign/daemon" )
AC_SUBST(cosigndb)

AC_ARG_WITH(cosignconf, AC_HELP_STRING([--with-cosignconf=FILE], [default cosign conf file location]), cosignconf="$withval", cosignconf="/usr/local/etc/cosign.conf" )
AC_SUBST(cosignconf)

AC_ARG_WITH(cosigncadir, AC_HELP_STRING([--with-cosigncadir=DIR], [default cosign CA dir location]), cosigncadir="$withval", cosigncadir="/var/cosign/certs/CA" )
AC_SUBST(cosigncadir)

AC_ARG_WITH(cosigncert, AC_HELP_STRING([--with-cosigncert=FILE], [default cosign
cert file location]), cosigncert="$withval", cosigncert="/var/cosign/certs/cert.pem" )
AC_SUBST(cosigncert)

AC_ARG_WITH(cosignkey, AC_HELP_STRING([--with-cosignkey=FILE], [default cosign
key file location]), cosignkey="$withval", cosignkey="/var/cosign/certs/key.pem" )
AC_SUBST(cosignkey)

AC_ARG_WITH(filterdb, AC_HELP_STRING([--with-filterdb=DIR], [default cosign filter database storage]), filterdb="$withval", filterdb="/var/cosign/filter" )
AC_SUBST(filterdb)

AC_ARG_WITH(cosignhost, AC_HELP_STRING([--with-cosignhost=NAME], [name of host that runs cosignd]), cosignhost="$withval", cosignhost="cosign.example.edu" )
AC_SUBST(cosignhost)

AC_ARG_WITH(cosignlogouturl, AC_HELP_STRING([--with-cosignlogouturl=URL], [default URL to redirect users to upon logout]), cosignlogouturl="$withval", cosignlogouturl="http://cosign.example.edu" )
AC_SUBST(cosignlogouturl)

AC_ARG_WITH(keytabpath, AC_HELP_STRING([--with-keytabpath=FILE], [path
to keytab]), keytabpath="$withval", keytabpath="" )
AC_SUBST(keytabpath)

CHECK_SSL

# Checks for filters:
CHECK_APACHE_APXS

if test "x_$FILTERS" = "x_" ; then
  AC_MSG_ERROR([No web server found])
fi
AC_SUBST(FILTERS)

for i in $FILTERS; do
  FILTER_CONFIG_FILES="$FILTER_CONFIG_FILES $i/Makefile"
done

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

# Misc.
if test x_$GCC = x_yes; then
    OPTOPTS=${OPTOPTS:-"-Wall -Wmissing-prototypes"}
fi
AC_SUBST(OPTOPTS)

AC_CONFIG_SUBDIRS(libsnet)

AC_CONFIG_FILES([Makefile
                 cgi/Makefile
		 common/Makefile
                 html/Makefile
                 daemon/Makefile
                 $FILTER_CONFIG_FILES
                 libcgi/Makefile])

AC_OUTPUT

AC_DEFUN([CHECK_SSL],
[
    AC_MSG_CHECKING(for ssl)
    ssldirs="/usr/local/openssl /usr/lib/openssl /usr/openssl \
        /usr/local/ssl /usr/lib/ssl /usr/ssl \
        /usr/pkg /usr/local /usr"
    AC_ARG_WITH(ssl,
        AC_HELP_STRING([--with-ssl=DIR], [path to ssl]),
        ssldirs="$withval")
    AC_CACHE_VAL(ac_cv_path_ssl,[
        for dir in $ssldirs; do
            ssldir="$dir"
            if test -f "$dir/include/openssl/ssl.h"; then
                ac_cv_path_ssl=$ssldir;
                break;
            fi
            if test -f "$dir/include/ssl.h"; then
                ac_cv_path_ssl=$ssldir;
                break
            fi
        done
    ])
    if test ! -e "$ac_cv_path_ssl" ; then
        AC_MSG_RESULT(cannot find ssl libraries)
    else
	CPPFLAGS="$CPPFLAGS -I$ac_cv_path_ssl/include";
	TLSDEFS=-DTLS;
	AC_SUBST(TLSDEFS)
	LIBS="$LIBS -lssl -lcrypto";
	LDFLAGS="$LDFLAGS -L$ac_cv_path_ssl/lib";
	HAVE_SSL=yes
	AC_SUBST(HAVE_SSL)
	AC_MSG_RESULT($ac_cv_path_ssl)
    fi
])

AC_DEFUN([CHECK_PROFILED],
[
    # Allow user to control whether or not profiled libraries are built
    AC_MSG_CHECKING(whether to build profiled libraries)
    PROFILED=true
    AC_ARG_ENABLE(profiled,
      [  --enable-profiled       build profiled libsnet (default=yes)],
      [test x_$enable_profiled = x_no && PROFILED=false]
    )
    AC_SUBST(PROFILED)
    if test x_$PROFILED = x_true ; then
      AC_MSG_RESULT(yes)
    else
      AC_MSG_RESULT(no)
    fi
])

m4_include([libtool.m4])


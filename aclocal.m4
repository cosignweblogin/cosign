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
        for ssldir in $ssldirs; do
            if test -f "$ssldir/include/openssl/ssl.h"; then
                ac_cv_path_ssl=$ssldir;
                break;
            fi
            if test -f "$ssldir/include/ssl.h"; then
                ac_cv_path_ssl=$ssldir;
                break
            fi
        done
    ])
    if test ! -e "$ac_cv_path_ssl" ; then
        AC_MSG_ERROR(cannot find ssl libraries)
    fi
    CPPFLAGS="$CPPFLAGS -I$ac_cv_path_ssl/include";
    TLSDEFS=-DTLS;
    AC_SUBST(TLSDEFS)
    LIBS="$LIBS -lssl -lcrypto";
    LDFLAGS="$LDFLAGS -L$ac_cv_path_ssl/lib";
    HAVE_SSL=yes
    AC_SUBST(HAVE_SSL)
    AC_MSG_RESULT($ac_cv_path_ssl)
])

AC_DEFUN([CHECK_LIBKRB],
[
    AC_MSG_CHECKING(for krb)
    krbdirs="/usr/local/kerberos /usr/lib/kerberos /usr/kerberos \
            /usr/local/krb5 /usr/lib/krb /usr/krb \
            /usr/pkg /usr/local /usr"
    AC_CACHE_VAL(ac_cv_path_krb,[
        for krbdir in $krbdirs; do
            if test -f "$krbdir/include/krb5.h"; then
                ac_cv_path_krb=$krbdir
                break;
            fi
        done
    ])
    if test ! -e "$ac_cv_path_krb" ; then
        AC_MSG_ERROR(cannot find krb libraries)
    fi
    KRBDEFS=-DKRB;
    AC_SUBST(KRBDEFS)
    KINC="-I$ac_cv_path_krb/include";
    AC_SUBST(KINC)
    KLIBS="-lkrb5 -lk5crypto -lcom_err";
    AC_SUBST(KLIBS)
    KLDFLAGS="-L$ac_cv_path_krb/lib";
    AC_SUBST(KLDFLAGS)
    HAVE_KRB=yes
    AC_SUBST(HAVE_KRB)
    AC_MSG_RESULT($ac_cv_path_krb)
])

AC_DEFUN([CHECK_KRB4],
[
    AC_MSG_CHECKING(for krb4)
    if test ! -e "$ac_cv_path_krb" ; then
        AC_MSG_ERROR(krb4 require krb5 libraries)
    fi
    K4DEFS=-DKRB4;
    AC_SUBST(K4DEFS)
    K4INC="-I$ac_cv_path_krb/include";
    AC_SUBST(K4INC)
    K4LIBS="-lkrb4 -lkrb524 -lkrb5 -lk5crypto -lcom_err";
    AC_SUBST(K4LIBS)
    K4LDFLAGS="-L$ac_cv_path_krb/lib";
    AC_SUBST(K4LDFLAGS)
    HAVE_KRB4=yes
    AC_SUBST(HAVE_KRB4)
    AC_MSG_RESULT($ac_cv_path_krb)
])

AC_DEFUN([CHECK_GSS],
[
    AC_MSG_CHECKING(for gss)
    if test ! -e "$ac_cv_path_krb" ; then
        AC_MSG_ERROR(gss require krb5 libraries)
    fi
    GSSDEFS=-DGSS;
    AC_SUBST(GSSDEFS)
    GSSINC="-I$ac_cv_path_krb/include";
    AC_SUBST(GSSINC)
    GSSLIBS="-lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err";
    AC_SUBST(GSSLIBS)
    GSSLDFLAGS="-L$ac_cv_path_krb/lib";
    AC_SUBST(GSSLDFLAGS)
    HAVE_GSS=yes
    AC_SUBST(HAVE_GSS)
    AC_MSG_RESULT($ac_cv_path_krb)
])

AC_DEFUN([CHECK_APACHE_APXS],
[
    AC_MSG_CHECKING([for Apache DSO support / apxs])
    AC_ARG_WITH(apache-apxs,
        AC_HELP_STRING([--with-apache-apxs=FILE], [path to Apache apxs program]),
        APXS=$withval)
    if test -f "$APXS" ; then
        ac_cv_path_apxs=$APXS   # put it into the cache
    else
        apxsdirs="$PATH:/usr/local/apache/bin:/usr/apache/bin:/usr/pkg/bin:/usr/local/bin:/usr/local/httpd/bin"
        AC_CACHE_VAL(ac_cv_path_apxs,[
            saved_ifs=$IFS
            IFS=:
            for i in $apxsdirs; do
                if test -f "$i/apxs"; then
                    ac_cv_path_apxs="$i/apxs"
                    break
                fi
            done
            IFS=$saved_ifs
        ])
        APXS="$ac_cv_path_apxs"
    fi
    if test -f "$APXS" ; then
        HAVE_APACHE=yes
        FILTERS="$FILTERS filters/apache"
        APXS_INCLUDE="-I`$APXS -q INCLUDEDIR`"
        APXS_CFLAGS="`$APXS -q CFLAGS`"
        APXS_CFLAGS_SHLIB="`$APXS -q CFLAGS_SHLIB`"
        APXS_SBINDIR="`$APXS -q SBINDIR`"
        APXS_TARGET="`$APXS -q TARGET`"
        if test x_$APXS_TARGET = x_httpd ; then
            APACHECTL="${APXS_SBINDIR}/apachectl"
        else
            APACHECTL="${APXS_SBINDIR}/${APXS_TARGET}ctl"
        fi
        AC_SUBST(APXS)
        AC_SUBST(APXS_INCLUDE)
        AC_SUBST(APXS_CFLAGS_SHLIB)
        AC_SUBST(APACHECTL)
        AC_MSG_RESULT($APXS)
    else
        AC_MSG_RESULT([not found - Apache filter support disabled])
    fi
])


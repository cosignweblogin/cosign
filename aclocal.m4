AC_DEFUN([CHECK_SSL],
[
    AC_MSG_CHECKING(for ssl)
    ssldirs="/usr/local/openssl /usr/lib/openssl /usr/openssl \
            /usr/local/ssl /usr/lib/ssl /usr/ssl \
            /usr/pkg /usr/local /usr"
    AC_ARG_WITH(ssl,
            AC_HELP_STRING([--with-ssl=DIR], [path to ssl]),
            ssldirs="$withval")
    for dir in $ssldirs; do
        ssldir="$dir"
        if test -f "$dir/include/openssl/ssl.h"; then
            found_ssl="yes";
            CPPFLAGS="$CPPFLAGS -I$ssldir/include";
            break;
        fi
        if test -f "$dir/include/ssl.h"; then
            found_ssl="yes";
            CPPFLAGS="$CPPFLAGS -I$ssldir/include";
            break
        fi
    done
    if test x_$found_ssl != x_yes; then
        AC_MSG_ERROR(cannot find ssl libraries)
    else
        TLSDEFS=-DTLS;
        AC_SUBST(TLSDEFS)
        LIBS="$LIBS -lssl -lcrypto";
        LDFLAGS="$LDFLAGS -L$ssldir/lib";
        HAVE_SSL=yes
    fi
    AC_SUBST(HAVE_SSL)
    AC_MSG_RESULT(yes)
])

AC_DEFUN([CHECK_LIBKRB],
[
    AC_MSG_CHECKING(for krb)
    krbdirs="/usr/local/kerberos /usr/lib/kerberos /usr/kerberos \
            /usr/local/krb5 /usr/lib/krb /usr/krb \
            /usr/pkg /usr/local /usr"
    AC_ARG_WITH(krb,
            AC_HELP_STRING([--with-krb=DIR], [path to krb]),
            krbdirs="$withval")
    for dir in $krbdirs; do
        krbdir="$dir"
        if test -f "$dir/include/krb5.h"; then
            found_krb="yes";
            KINC="-I$krbdir/include";
	    AC_SUBST(KINC)
            break;
        fi
    done
    if test x_$found_krb != x_yes; then
        AC_MSG_ERROR(cannot find krb libraries)
    else
        TLSDEFS=-DTLS;
        AC_SUBST(TLSDEFS)
        KLIBS="-lkrb5 -lk5crypto -lcom_err";
	AC_SUBST(KLIBS)
        KLDFLAGS="-L$krbdir/lib";
	AC_SUBST(KLDFLAGS)
        HAVE_KRB=yes
    fi
    AC_SUBST(HAVE_KRB)
    AC_MSG_RESULT(yes)
])

AC_DEFUN([CHECK_APACHE],
[
    AC_MSG_CHECKING(for apache)
    apachedirs="/usr/local/apache /usr/apache \
            /usr/pkg /usr/local /usr /usr/local/httpd"
    AC_ARG_WITH(apache,
            AC_HELP_STRING([--with-apache=DIR], [path to apache]),
            apachedirs="$withval")
    for dir in $apachedirs; do
        apachedir="$dir"
        if test -f "$dir/include/httpd/http_core.h"; then
            found_apache="yes";
            break
        fi
        if test -f "$dir/include/http_core.h"; then
            found_apache="yes";
            break
        fi
        if test -f "$dir/include/apache/http_core.h"; then
            found_apache="yes";
            break
        fi
    done
    if test x_$found_apache != x_yes; then
        AC_MSG_ERROR(cannot find apache )
    else
        HAVE_APACHE=yes
    fi
    AC_SUBST(HAVE_APACHE)
    AC_MSG_RESULT(yes)
])

AC_DEFUN([CHECK_APACHE_APXS],
[
    if test x_$HAVE_APACHE = x_yes; then
        AC_MSG_CHECKING(for apache DSO support)
        AC_ARG_WITH(apxs,
                AC_HELP_STRING([--with-apxs=FILE], [path to apxs]),
                apxspath="$withval")
        if test -n "$apxspath" -a -f "$apxspath"; then
            found_apxs="yes"
        else
            dirs=$apachedir/bin:$PATH:/usr/local/apache/bin
            saved_ifs=$IFS
            IFS=:
            for i in $dirs; do
                apxspath=$i/apxs
                if test -f "$apxspath"; then
                    found_apxs="yes"
                    break
                fi
            done
            IFS=$saved_ifs
        fi
        if test x_$found_apxs != x_yes; then
            AC_MSG_ERROR(cannot find apxs )
        fi
        APXS_INCLUDE="-I`$apxspath -q INCLUDEDIR`"
        APXS_CFLAGS_SHLIB="`$apxspath -q CFLAGS_SHLIB`"
        AC_SUBST(apxspath)
        AC_SUBST(APXS_INCLUDE)
        AC_SUBST(APXS_CFLAGS_SHLIB)
        AC_MSG_RESULT($apxspath)
    fi
])


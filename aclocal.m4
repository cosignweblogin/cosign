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
    case "X$host_os" in 
    Xaix*)
	ADDLIBS="-lssl -lcrypto";
	AC_SUBST(ADDLIBS)
	ADDLDFLAGS="-L$ac_cv_path_ssl/lib";
	AC_SUBST(ADDLDFLAGS)
    ;;
    esac

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
    KRBCGI="cosign.cgi"
    AC_SUBST(KRBCGI)
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

AC_DEFUN([CHECK_APACHE2_APXS],
[
    AC_MSG_CHECKING(for apache 2)
    apxs2dirs="/usr/local/apache2/bin /usr/apache2/bin /usr/pkg/bin \
    /usr/local/bin /usr/local/httpd/bin"
    AC_CACHE_VAL(ac_cv_path_apxs2,[
        for i in $apxs2dirs; do
	    if test -f "$i/apxs"; then
		ac_cv_path_apxs2="$i/apxs"
                break;
            fi
        done
    ])
    APXS2="$ac_cv_path_apxs2"

    if test ! -e "$ac_cv_path_apxs2" ; then
        AC_MSG_ERROR(cannot find apache 2)
    fi

    FILTERS="$FILTERS filters/apache2"
    APXS2_INCLUDE="-I`$APXS2 -q INCLUDEDIR`"
    APXS2_CFLAGS="`$APXS2 -q CFLAGS`"
    APXS2_CFLAGS_SHLIB="`$APXS2 -q CFLAGS_SHLIB`"
    APXS2_SBINDIR="`$APXS2 -q SBINDIR`"
    APXS2_TARGET="`$APXS2 -q TARGET`"
    if test x_$APXS2_TARGET = x_httpd ; then
	APACHECTL2="${APXS2_SBINDIR}/apachectl"
    else
	APACHECTL2="${APXS2_SBINDIR}/${APXS2_TARGET}ctl"
    fi
    AC_SUBST(APXS2)
    AC_SUBST(APXS2_INCLUDE)
    AC_SUBST(APXS2_CFLAGS)
    AC_SUBST(APXS2_CFLAGS_SHLIB)
    AC_SUBST(APACHECTL2)
    HAVE_APACHE2=yes
    AC_SUBST(HAVE_APACHE2)
    AC_MSG_RESULT($ac_cv_path_apxs2)
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
        AC_SUBST(APXS_CFLAGS)
        AC_SUBST(APXS_CFLAGS_SHLIB)
        AC_SUBST(APACHECTL)
        AC_MSG_RESULT($APXS)
    else
        AC_MSG_RESULT([not found - Apache filter support disabled])
    fi
])


AC_DEFUN([CGI_BASICAUTH],
[
    BASICCGI="basicosign.cgi"
    AC_SUBST(BASICCGI)
    AC_MSG_RESULT([BasicAuth cgi will be built])
])

AC_DEFUN([CHECK_LIBMYSQL],
[
    AC_MSG_CHECKING(for mysql)
    mysqldirs="/usr /usr/local/mysql /usr/lib/mysql /usr/mysql \
            /usr/pkg /usr/local /usr"
    AC_CACHE_VAL(ac_cv_path_mysql,[
        for mysqldir in $mysqldirs; do
            if test -f "$mysqldir/include/mysql/mysql.h"; then
                ac_cv_path_mysql=$mysqldir
                break;
            fi
        done
    ])
    if test ! -e "$ac_cv_path_mysql" ; then
        AC_MSG_ERROR(cannot find mysql libraries)
    fi
    MYSQLINC="-I$ac_cv_path_mysql/include/mysql";
    AC_SUBST(MYSQLINC)
    MYSQLLIBS="-lmysqlclient";
    AC_SUBST(MYSQLLIBS)
    MYSQLLDFLAGS="-L$ac_cv_path_mysql/lib/mysql -R$ac_cv_path_mysql/lib/mysql";
    AC_SUBST(MYSQLLDFLAGS)
    HAVE_MYSQL=yes
    AC_SUBST(HAVE_MYSQL)
    AC_MSG_RESULT($ac_cv_path_mysql)
])

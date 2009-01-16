AC_DEFUN([CHECK_UNIVERSAL_BINARIES],
[
    AC_ARG_ENABLE(universal_binaries,
        AC_HELP_STRING([--enable-universal-binaries], [build universal binaries (default=no)]),
        ,[enable_universal_binaries=no])
    if test "${enable_universal_binaries}" = "yes"; then
        case "${host_os}" in
	  darwin8*)
            macosx_sdk="MacOSX10.4u.sdk"
            ;;

          darwin9*)
            dep_target="-mmacosx-version-min=10.4"
            macosx_sdk="MacOSX10.5.sdk"
	    ;;

          *)
            AC_MSG_ERROR([Building universal binaries on ${host_os} is not supported])
            ;;
        esac

        echo ===========================================================
        echo Setting up universal binaries for ${host_os}
        echo ===========================================================
	OPTOPTS="-isysroot /Developer/SDKs/$macosx_sdk -arch i386 -arch x86_64 -arch ppc -arch ppc64 $dep_target"
    fi
])

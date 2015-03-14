#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(dnsforwarder, 0.0, https://github.com/holmium/dnsforwarder/issues)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([dnscache.h])
AC_CONFIG_HEADERS(config.h)

AC_ARG_WITH([ccflags],
    [AS_HELP_STRING([--with-ccflags],
        [clear $CFLAGS (default=yes)]
    )],
	[   case "${withval}" in
	    yes) [CFLAGS=""] ;;
	    no)  [] ;;
	    *)   AC_MSG_ERROR(bad value ${withval} for --with-ccflags) ;;
	    esac
	],
    [CFLAGS=""]
    )
    
LDFLAGS=" ${LDFLAGS} -pthread "
CFLAGS=" ${CFLAGS} -pthread "

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# Checks for math libraries.
AC_CHECK_LIB(m, log, , 
	AC_MSG_ERROR(No libmath found.)
	)
AC_CHECK_LIB(m, sqrt, , 
	AC_MSG_ERROR(No libmath found.)
	)

AC_ARG_ENABLE([win],
	[AS_HELP_STRING([--enable-win],
	    [compile for win32 (default=no)]
	)],
	[   case "${enableval}" in
	    yes)  [WIN32=yes];;
	    no)   [WIN32=no];;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-win) ;;
	    esac
	],
	[WIN32=no]
	)

if test "$WIN32" == "yes"
then
CFLAGS="${CFLAGS} -DWIN32 "
fi

if test "$WIN32" != "yes"
then
	AC_ARG_ENABLE([android],
		[AS_HELP_STRING([--enable-android],
			[compile for android (default=no)]
		)],
		[   case "${enableval}" in
			yes)  [ANDROID=yes];;
			no)   [ANDROID=no];;
			*)   AC_MSG_ERROR(bad value ${enableval} for --enable-android) ;;
			esac
		],
		[ANDROID=no]
		)

	if test "$ANDROID" == "yes"
	then
	CFLAGS="${CFLAGS} -DANDROID "
	fi

	AC_ARG_ENABLE([downloader],
		[AS_HELP_STRING([--enable-downloader],
			[downloader, libcurl, wget, or no (default=libcurl)]
		)],
		[   case "${enableval}" in
			libcurl)    DOWNLOADER=libcurl;;
			wget)       DOWNLOADER=wget;;
			no)         DOWNLOADER=no;;
			*)          AC_MSG_ERROR(bad value ${enableval} for --enable-downloader) ;;
			esac
		],
		[DOWNLOADER=libcurl]
		)

	if test "$DOWNLOADER" == "libcurl" 
	then 

	# Checks for curl.
	AC_CHECK_LIB(curl, curl_global_init, ,
		AC_MSG_ERROR(No libcurl found.)
		)

	CFLAGS="${CFLAGS} -DDOWNLOAD_LIBCURL "
	fi

	if test "$DOWNLOADER" == "wget" 
	then
	CFLAGS="${CFLAGS} -DDOWNLOAD_WGET "
	fi

	if test "$DOWNLOADER" == "no" 
	then
	CFLAGS="${CFLAGS} -DNODOWNLOAD "
	fi

	AC_ARG_ENABLE([base64decoder],
		[AS_HELP_STRING([--enable-base64decoder],
			[base64decoder, openssl or coreutils or uudecode (default=openssl)]
		)],
		[   case "${enableval}" in
			openssl)    BASE64DECODER=openssl;;
			uudecode)   BASE64DECODER=uudecode;;
			coreutils)  BASE64DECODER=coreutils;;
			*)          AC_MSG_ERROR(bad value ${enableval} for --enable-base64decoder) ;;
			esac
		],
		[BASE64DECODER=openssl]
		)

	if test "$BASE64DECODER" == "openssl" 
	then 
	CFLAGS="${CFLAGS} -DBASE64_DECODER_OPENSSL "
	# Checks for openssl.
	AC_CHECK_LIB(crypto, BIO_new, ,
		AC_MSG_ERROR(No openssl found.)
		)
	fi

	if test "$BASE64DECODER" == "uudecode" 
	then
	CFLAGS="${CFLAGS} -DBASE64_DECODER_UUDECODE "
	fi

	if test "$BASE64DECODER" == "coreutils"
	then
	CFLAGS="${CFLAGS} -DBASE64_DECODER_COREUTILS "
	fi

	# Checks for header files.
	AC_CHECK_HEADERS([sys/syscall.h wordexp.h])

	if test "$DOWNLOADER" == "libcurl"
	then
	AC_CHECK_HEADERS([curl/curl.h],
					 [],
					 AC_MSG_ERROR(No libcurl headers found.),
					 []
					 )
	fi

	if test "$BASE64DECODER" == "openssl" 
	then 
	AC_CHECK_HEADERS([openssl/evp.h openssl/bio.h],
					 [],
					 AC_MSG_ERROR(No openssl headers found.),
					 []
					 )
	fi

	# Checks for library functions.
	AC_FUNC_FORK
	AC_FUNC_MALLOC
	AC_FUNC_REALLOC
	AC_CHECK_FUNC(setenv, AC_DEFINE(HAVE_SETENV, [], [setenv]), AC_MSG_WARN(Relative path is not supported.))
	AC_CHECK_FUNC(wordexp, AC_DEFINE(HAVE_WORDEXP, [], [wordexp]), AC_MSG_WARN(Relative path is not supported.))

	AC_ARG_ENABLE([spinlock],
		[AS_HELP_STRING([--enable-spinlock],
			[spinlock will be used (default=yes)]
		)],
		[   case "${enableval}" in
			yes)  AC_CHECK_FUNCS([pthread_spin_init]) ;;
			no)   [];;
			*)   AC_MSG_ERROR(bad value ${enableval} for --enable-spinlock) ;;
			esac
		],
		[]
		)
		
	AC_ARG_ENABLE([rwlock],
		[AS_HELP_STRING([--enable-rwlock],
			[rwlock will be used (default=yes)]
		)],
		[   case "${enableval}" in
			yes)  AC_CHECK_FUNCS([pthread_rwlock_init]) ;;
			no)   [];;
			*)   AC_MSG_ERROR(bad value ${enableval} for --enable-rwlock) ;;
			esac
		],
		[]
		)
		
	AC_TYPE_PID_T
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
	    [enable DEBUG mode (default=no)]
	)],
	[   case "${enableval}" in
	    yes) [CFLAGS="${CFLAGS} -DDEBUG -g -Wall "] ;;
	    no)  [CFLAGS="${CFLAGS} -O2 "] ;;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
	    esac
	],
	[CFLAGS="${CFLAGS} -O2 "]
	)
	
AC_ARG_ENABLE([static],
	[AS_HELP_STRING([--enable-static],
	    [static link (default=no)]
	)],
	[   case "${enableval}" in
	    yes)  [CFLAGS="${CFLAGS} -static "];;
	    no)   [];;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-static) ;;
	    esac
	],
	[]
	)

AC_CONFIG_FILES([makefile])
AC_OUTPUT

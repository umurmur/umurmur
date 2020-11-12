# Copyright (C) 2011, Antoine Bertin <diaoulael@gmail.com>
# Copyright (C) 2011-2014, Martin Johansson <martin@fatbob.nu>
#
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  - Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  - Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#  - Neither the name of the Developers nor the names of its contributors may
#    be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.63])
AC_INIT([umurmur], [0.2.17], [https://github.com/umurmur/umurmur/issues/new], [umurmur], [http://github.com/umurmur/umurmur])
AC_CONFIG_SRCDIR([src/client.h])
AC_CONFIG_HEADERS([src/config.h:config.h.in])
AM_INIT_AUTOMAKE
AC_CANONICAL_HOST
AM_SILENT_RULES([yes])

# Configure options.
AC_ARG_WITH([ssl], [AC_HELP_STRING([--with-ssl=@<:@LIB@:>@], [SSL library (openssl|polarssl|gnutls|mbedtls) @<:@default=polarssl@:>@])], [], [with_ssl=polarssl])
AC_ARG_ENABLE([shmapi], [AC_HELP_STRING([--enable-shmapi], [compile with Sharedmemory API support @<:@default=no@:>@])],[],[enable_shmapi=no] )
AC_ARG_ENABLE(polarssl-test-cert, [  --enable-polarssl-test-cert  Link to PolarSSL test certificate and key @<:@default=no@:>@], [enable_polarssl_test_cert=yes])
AC_ARG_ENABLE(polarssl-havege, [  --enable-polarssl-havege  Link to PolarSSL HAVEGE random generator key @<:@default=no@:>@ Default: /dev/urandom], [enable_polarssl_havege=yes])
AC_ARG_ENABLE(mbedtls-test-cert, [  --enable-mbedtls-test-cert  Link to mbedTLS test certificate and key @<:@default=no@:>@], [enable_mbedtls_test_cert=yes])
AC_ARG_ENABLE(mbedtls-havege, [  --enable-mbedtls-havege  Link to mbedTLS HAVEGE random generator key @<:@default=no@:>@ Default: /dev/urandom], [enable_mbedtls_havege=yes])

# Checks for programs.
AC_PROG_CC

# Checks dependencies.
AC_CHECK_HEADERS([google/protobuf-c/protobuf-c.h], [], [AC_MSG_ERROR([could not find google/protobuf-c/protobuf-c.h])])
AC_CHECK_LIB([protobuf-c], [protobuf_c_message_init], [], [AC_MSG_ERROR([could not find protobuf-c library])])
AC_CHECK_HEADERS([libconfig.h], [], [AC_MSG_ERROR([could not find libconfig.h])])
AC_CHECK_LIB([config], [config_init], [], [AC_MSG_ERROR([could not find libconfig])])
case $host_os in
  darwin* )
    AC_CHECK_FUNC([clock_get_time], [], [AC_MSG_ERROR([could not find clock_get_time()])])
    CFLAGS+=" -Wno-deprecated-declarations"
    ;;
  * )
    AC_CHECK_FUNC([clock_gettime], [], [AC_CHECK_LIB([rt], [clock_gettime], [], [AC_MSG_ERROR([could not find clock_gettime() in librt])])])
    ;;
esac
AS_IF([test "x$with_ssl" = xpolarssl], [
	AC_CHECK_HEADERS([polarssl/ssl.h], [], [AC_MSG_ERROR([could not find polarssl/ssl.h])])
	AC_CHECK_HEADERS([polarssl/version.h], [], [AC_MSG_ERROR([could not find polarssl/version.h])])

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <polarssl/ssl.h>]],
		[[#if defined(POLARSSL_ZLIB_SUPPORT)
		int x;
		#endif
		x = 0;
		return 0;]])],
		[AC_CHECK_LIB([z], [deflate], [], [AC_MSG_ERROR([could not find zlib])])],
		[])
	AC_CHECK_LIB([polarssl], [ssl_init], [], [AC_MSG_ERROR([could not find libpolarssl])])
	AC_DEFINE([USE_POLARSSL], [], [Use PolarSSL])
    AS_IF([test "x$enable_polarssl_test_cert" = xyes], [
	    AC_CHECK_LIB([polarssl], [test_srv_crt], [], [AC_MSG_ERROR([could not find test_srv_crt])])
	    AC_DEFINE([USE_POLARSSL_TESTCERT], [], [Use PolarSSL test certificate])
    ])
    AS_IF([test "x$enable_polarssl_havege" = xyes], [
	    AC_CHECK_LIB([polarssl], [havege_init], [], [AC_MSG_ERROR([could not find havege_init])])
	    AC_DEFINE([USE_POLARSSL_HAVEGE], [], [Use PolarSSL HAVEGE random generator])
    ])
])
AS_IF([test "x$with_ssl" = xmbedtls], [
	AC_CHECK_HEADERS([mbedtls/ssl.h], [], [AC_MSG_ERROR([could not find mbedtls/ssl.h])])
	AC_CHECK_HEADERS([mbedtls/version.h], [], [AC_MSG_ERROR([could not find mbedtls/version.h])])

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <mbedtls/ssl.h>]],
		[[#if defined(MBEDTLS_ZLIB_SUPPORT)
		int x;
		#endif
		x = 0;
		return 0;]])],
		[AC_CHECK_LIB([z], [deflate], [], [AC_MSG_ERROR([could not find zlib])])],
		[])
	AC_CHECK_LIB([mbedtls], [mbedtls_ssl_init], [], [AC_MSG_ERROR([could not find libmbedtls])], [-lmbedcrypto -lmbedx509])
	AC_CHECK_LIB([mbedcrypto], [mbedtls_cipher_setup], [], [AC_MSG_ERROR([could not find libmbedcrypto])], [-lmbedtls -lmbedx509])
	AC_CHECK_LIB([mbedx509], [mbedtls_x509_crt_init], [], [AC_MSG_ERROR([could not find libmbedx509])], [-lmbedcrypto -lmbedtls])
	AC_DEFINE([USE_MBEDTLS], [], [Use mbedTLS])
    AS_IF([test "x$enable_mbedtls_test_cert" = xyes], [
	    AC_CHECK_LIB([mbedtls], [test_srv_crt], [], [AC_MSG_ERROR([could not find test_srv_crt])])
	    AC_DEFINE([USE_MBEDTLS_TESTCERT], [], [Use mbedTLS test certificate])
    ])
    AS_IF([test "x$enable_mbedtls_havege" = xyes], [
	    AC_CHECK_HEADERS([mbedtls/havege.h], [], [AC_MSG_ERROR([could not find mbedtls/havege.h])])
	    AC_CHECK_LIB([mbedcrypto], [mbedtls_havege_init], [], [AC_MSG_ERROR([could not find mbedtls_havege_init])])
	    AC_DEFINE([USE_MBEDTLS_HAVEGE], [], [Use mbedTLS HAVEGE random generator])
    ])
])
AS_IF([test "x$with_ssl" = xopenssl], [
	AC_CHECK_HEADERS([openssl/ssl.h], [], [AC_MSG_ERROR([could not find openssl/ssl.h])])
	AC_CHECK_LIB([crypto], [CRYPTO_new_ex_data], [], [AC_MSG_ERROR([could not find libcrypto])])
	AC_CHECK_LIB([ssl], [SSL_new], [], [AC_MSG_ERROR([could not find libssl])])
])
AS_IF([test "x$with_ssl" = xgnutls], [
	AC_CHECK_HEADERS([gnutls/gnutls.h], [], [AC_MSG_ERROR([could not find gnutls/gnutls.h])])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([@%:@include <gnutls/gnutls.h>],
                    [ #ifdef GNUTLS_E_PREMATURE_TERMINATION
                      #else
                      #error Unsuitable version of GnuTLS
                      #endif
                      ])], [], [AC_MSG_ERROR([Unsuitable version of GnuTL, minimum required is 3.0])])
	AC_CHECK_LIB([gnutls], [gnutls_priority_init], [], [AC_MSG_ERROR([could not find libgnutls])])
	AC_CHECK_LIB([nettle], [_nettle_aes_decrypt], [], [AC_MSG_ERROR([could not find libnettle])])
	AC_DEFINE([USE_GNUTLS], [], [Use GnuTLS])
])

AM_CONDITIONAL(USE_OPENSSL, test x$with_ssl = xopenssl)
AM_CONDITIONAL(USE_GNUTLS, test x$with_ssl = xgnutls)
AM_CONDITIONAL(USE_MBEDTLS, test x$with_ssl = xmbedtls)

AS_IF([test "x$enable_shmapi" != xno],
	[
	AM_CONDITIONAL(USE_SHAREDMEMORY_API, true)
	AC_DEFINE([USE_SHAREDMEMORY_API],[],[Use sharedmemory API])
    AC_CHECK_FUNC([shm_open], [], [AC_CHECK_LIB([rt], [shm_open], [], [AC_MSG_ERROR([could not find shm_open() in librt])])])
	], [
	AM_CONDITIONAL(USE_SHAREDMEMORY_API, false)
])

AC_DEFINE([DEFAULT_CONFIG], ["/etc/umurmur.conf"], [Default config])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netinet/tcp.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h poll.h], [], [AC_MSG_ERROR([missing a required header])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([ftruncate gettimeofday inet_ntoa memchr memmove memset socket strdup strrchr uname poll], [], [AC_MSG_ERROR([missing a required func])])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

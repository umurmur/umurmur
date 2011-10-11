# Copyright (C) 2011, Antoine Bertin <diaoulael@gmail.com>
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
AC_INIT([umurmur], [0.2.8], [http://code.google.com/p/umurmur/issues/entry], [umurmur], [http://code.google.com/p/umurmur])
AC_CONFIG_SRCDIR([src/client.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Configure options.
AC_ARG_WITH([ssl], [AC_HELP_STRING([--with-ssl=@<:@LIB@:>@], [SSL library (openssl|polarssl) @<:@default=polarssl@:>@])], [], [with_ssl=polarssl])

# Checks for programs.
AC_PROG_CC

# Checks dependencies.
AC_CHECK_HEADERS([google/protobuf-c/protobuf-c.h], [], [AC_MSG_ERROR([could not find google/protobuf-c/protobuf-c.h])])
AC_CHECK_LIB([protobuf-c], [protobuf_c_data_buffer_init], [], [AC_MSG_ERROR([could not find protobuf-c library])])
AC_CHECK_HEADERS([libconfig.h], [], [AC_MSG_ERROR([could not find libconfig.h])])
AC_CHECK_LIB([config], [config_init], [], [AC_MSG_ERROR([could not find libconfig])])
AS_IF([test "x$with_ssl" = xpolarssl], [
	AC_CHECK_HEADERS([polarssl/ssl.h], [], [AC_MSG_ERROR([could not find polarssl/ssl.h])])
	AC_CHECK_LIB([polarssl], [ssl_init], [], [AC_MSG_ERROR([could not find libpolarssl])])
	AC_DEFINE([USE_POLARSSL], [], [Use PolarSSL])
])
AS_IF([test "x$with_ssl" = xopenssl], [
	AC_CHECK_HEADERS([openssl/ssl.h], [], [AC_MSG_ERROR([could not find openssl/ssl.h])])
	AC_CHECK_LIB([crypto], [BN_init], [], [AC_MSG_ERROR([could not find libcrypto])])
	AC_CHECK_LIB([ssl], [SSL_library_init], [], [AC_MSG_ERROR([could not find libssl])])
])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netinet/tcp.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h sys/poll.h], [], [AC_MSG_ERROR([missing a required header])])

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
AC_CHECK_FUNCS([ftruncate gettimeofday inet_ntoa memchr memmove memset socket strdup strerror strrchr uname poll], [], [AC_MSG_ERROR([missing a required func])])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

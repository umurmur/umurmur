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
AM_CFLAGS=-std=gnu99 -Wall -Wextra -Werror -D_XOPEN_SOURCE -D_GNU_SOURCE

bin_PROGRAMS=umurmurd
umurmurd_SOURCES=client.c main.c messages.c pds.c server.c log.c conf.c crypt.c timer.c messagehandler.c channel.c Mumble.pb-c.c voicetarget.c ban.c util.c memory.c

if USE_OPENSSL
umurmurd_SOURCES+=ssli_openssl.c
else
if USE_GNUTLS
umurmurd_SOURCES+=ssli_gnutls.c
else
if USE_MBEDTLS
umurmurd_SOURCES+=ssli_mbedtls.c
else
umurmurd_SOURCES+=ssli_polarssl.c
endif
endif
endif

if USE_SHAREDMEMORY_API
umurmurd_SOURCES+=sharedmemory.c
endif

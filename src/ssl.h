/* Copyright (C) 2009-2010, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2010, Thorvald Natvig <thorvald@natvig.com>

   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   - Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
   - Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
   - Neither the name of the Developers nor the names of its contributors may
     be used to endorse or promote products derived from this software without
     specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef SSL_H_987698
#define SSL_H_987698

#ifdef USE_POLARSSL
#include <polarssl/ssl.h>
#else
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#endif

#include "types.h"
#include <inttypes.h>

#ifdef USE_POLARSSL
#define SSLI_ERROR_WANT_READ -0x0F300 /* PolarSSL uses -0x0f00 -> --0x0f90 */
#define SSLI_ERROR_WANT_WRITE -0x0F310
#define SSLI_ERROR_ZERO_RETURN POLARSSL_ERR_NET_CONN_RESET
#define SSLI_ERROR_CONNRESET POLARSSL_ERR_NET_CONN_RESET
#define SSLI_ERROR_SYSCALL POLARSSL_ERR_NET_RECV_FAILED

typedef	ssl_context SSL_handle_t;

#else

#define SSLI_ERROR_WANT_READ SSL_ERROR_WANT_READ
#define SSLI_ERROR_WANT_WRITE SSL_ERROR_WANT_WRITE
#define SSLI_ERROR_ZERO_RETURN SSL_ERROR_ZERO_RETURN
#define SSLI_ERROR_CONNRESET SSL_ERROR_ZERO_RETURN
#define SSLI_ERROR_SYSCALL SSL_ERROR_SYSCALL

typedef SSL SSL_handle_t;

#endif

void SSLi_init(void);
void SSLi_deinit(void);
SSL_handle_t *SSLi_newconnection(int *fd, bool_t *SSLready);
void SSLi_closeconnection(SSL_handle_t *ssl);
int SSLi_nonblockaccept(SSL_handle_t *ssl, bool_t *SSLready);

int SSLi_read(SSL_handle_t *ssl, uint8_t *buf, int len);
int SSLi_write(SSL_handle_t *ssl, uint8_t *buf, int len);
int SSLi_get_error(SSL_handle_t *ssl, int code);
bool_t SSLi_data_pending(SSL_handle_t *ssl);
void SSLi_shutdown(SSL_handle_t *ssl);
void SSLi_free(SSL_handle_t *ssl);

#endif

/* Copyright (C) 2009-2015, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2015, Thorvald Natvig <thorvald@natvig.com>
   Copyright (C) 2015-2015, Szymon Pusz <szymon@pusz.net>

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
#include "conf.h"
#include "log.h"
#include "ssl.h"
#include "memory.h"

#include <stdlib.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

const int ciphers[] =
{
	MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
	MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	0
};

static mbedtls_x509_crt certificate;
static mbedtls_pk_context key;
bool_t builtInTestCertificate;

static inline int x509parse_keyfile(mbedtls_pk_context *pk, const char *path, const char *pwd)
{
	mbedtls_pk_init(pk);
	return mbedtls_pk_parse_keyfile(pk, path, pwd);
}

static void initCert()
{
	int rc;
	char *crtfile = (char *)getStrConf(CERTIFICATE);

	if (crtfile == NULL) {
		Log_fatal("No certificate file specified");
		return;
	}

	rc = mbedtls_x509_crt_parse_file(&certificate, crtfile);
	if (rc != 0) {
		char buffer[128];
		mbedtls_strerror(rc, buffer, sizeof(buffer));
		Log_fatal("Could not parse certificate file %s: %s", crtfile, buffer);
	}
}

static void initKey()
{
	int rc;
	char *keyfile = (char *)getStrConf(KEY);

	if (keyfile == NULL)
		Log_fatal("No key file specified");

	rc = x509parse_keyfile(&key, keyfile, NULL);
	if (rc != 0) {
		char buffer[128];
		mbedtls_strerror(rc, buffer, sizeof(buffer));
		Log_fatal("Could not read private key file %s: %s", keyfile, buffer);
	}
}

#define DEBUG_LEVEL 3
static void pssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	(void)ctx;
	(void)file;
	(void)line;
	if (level <= DEBUG_LEVEL)
		Log_info("mbedTLS [level %d]: %s", level, str);
}

mbedtls_ssl_config *conf;

void SSLi_init(void)
{
	int rc;

	if (psa_crypto_init() != PSA_SUCCESS)
		Log_fatal("psa_crypto_init failed");

	initCert();
	initKey();

	conf = Memory_safeCalloc(1, sizeof(mbedtls_ssl_config));
	if (!conf)
		Log_fatal("Out of memory");

	mbedtls_ssl_config_init(conf);

	if ((rc = mbedtls_ssl_config_defaults(conf,
			MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
		Log_fatal("mbedtls_ssl_config_defaults returned %d", rc);

	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_dbg(conf, pssl_debug, NULL);
	mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_ciphersuites(conf, (const int *)&ciphers);
	mbedtls_ssl_conf_ca_chain(conf, &certificate, NULL);

	if ((rc = mbedtls_ssl_conf_own_cert(conf, &certificate, &key)) != 0)
		Log_fatal("mbedtls_ssl_conf_own_cert returned %d", rc);

	Log_info("Mbed TLS library initialized (version: %s)", MBEDTLS_VERSION_STRING);
}

void SSLi_deinit(void)
{
	mbedtls_ssl_config_free(conf);
	free(conf);
	mbedtls_x509_crt_free(&certificate);
	mbedtls_pk_free(&key);
	mbedtls_psa_crypto_free();
}

bool_t SSLi_getSHA1Hash(SSL_handle_t *ssl, uint8_t *hash)
{
	mbedtls_x509_crt const *cert;
	size_t hash_length;

	cert = mbedtls_ssl_get_peer_cert(ssl);
	if (!cert)
		return false;

	if (psa_hash_compute(
		    PSA_ALG_SHA_1, cert->raw.p, cert->raw.len, hash,
		    20, &hash_length) != PSA_SUCCESS)
		return false;

	return hash_length == 20;
}

SSL_handle_t *SSLi_newconnection(int *fd, bool_t *SSLready)
{
	mbedtls_ssl_context *ssl;
	mbedtls_ssl_session *ssn;
	int rc;
	(void)SSLready;

	ssl = Memory_safeCalloc(1, sizeof(mbedtls_ssl_context));
	ssn = Memory_safeCalloc(1, sizeof(mbedtls_ssl_session));
	if (!ssl || !ssn)
		Log_fatal("Out of memory");

	mbedtls_ssl_init(ssl);
	mbedtls_ssl_set_bio(ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	mbedtls_ssl_set_session(ssl, ssn);

	if ((rc = mbedtls_ssl_setup(ssl, conf)) != 0)
		Log_fatal("mbedtls_ssl_setup returned %d", rc);

	return ssl;
}

int SSLi_nonblockaccept(SSL_handle_t *ssl, bool_t *SSLready)
{
	int rc;

	rc = mbedtls_ssl_handshake(ssl);
	if (rc != 0) {
		if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			return 0;
		if (rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
			return 0;
		Log_warn("SSL handshake failed: %d", rc);
		return -1;
	}
	*SSLready = true;
	return 0;
}

int SSLi_read(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	int rc;

	rc = mbedtls_ssl_read(ssl, buf, len);
	if (rc == MBEDTLS_ERR_SSL_WANT_READ)
		return SSLI_ERROR_WANT_READ;
	return rc;
}

int SSLi_write(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	int rc;

	rc = mbedtls_ssl_write(ssl, buf, len);
	if (rc == MBEDTLS_ERR_SSL_WANT_WRITE)
		return SSLI_ERROR_WANT_WRITE;
	return rc;
}

int SSLi_get_error(SSL_handle_t *ssl, int code)
{
	(void)ssl;
	return code;
}

bool_t SSLi_data_pending(SSL_handle_t *ssl)
{
	return mbedtls_ssl_get_bytes_avail(ssl) > 0;
}

void SSLi_shutdown(SSL_handle_t *ssl)
{
	mbedtls_ssl_close_notify(ssl);
}

void SSLi_free(SSL_handle_t *ssl)
{
	Log_debug("SSLi_free");
	mbedtls_ssl_free(ssl);
	free(ssl);
}

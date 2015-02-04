/* Copyright (C) 2009-2014, Martin Johansson <martin@fatbob.nu>
   Copyright (C) 2005-2014, Thorvald Natvig <thorvald@natvig.com>

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

#include <stdlib.h>
#include <fcntl.h>

#include <polarssl/config.h>
#include <polarssl/havege.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/ssl.h>
#include <polarssl/net.h>

#ifdef POLARSSL_API_V1_2_ABOVE
int ciphers[] =
{
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    0
};
#else
int ciphers[] =
{
    SSL_EDH_RSA_AES_256_SHA,
    SSL_RSA_AES_256_SHA,
    SSL_RSA_AES_128_SHA,
    0
};
#endif

#ifdef POLARSSL_API_V1_3_ABOVE
static x509_crt certificate;
static inline int x509parse_keyfile(rsa_context *rsa, const char *path,
                                    const char *pwd)
{
    int ret;
    pk_context pk;

    pk_init(&pk);
    ret = pk_parse_keyfile(&pk, path, pwd);
    if (ret == 0 && !pk_can_do( &pk, POLARSSL_PK_RSA))
        ret = POLARSSL_ERR_PK_TYPE_MISMATCH;
    if (ret == 0)
        rsa_copy(rsa, pk_rsa(pk));
    else
        rsa_free(rsa);
    pk_free(&pk);
    return ret;
}
#else
static x509_cert certificate;
#endif

static rsa_context key;
bool_t builtInTestCertificate;

#ifdef USE_POLARSSL_HAVEGE
havege_state hs;
#else
int urandom_fd;
#endif

/* DH prime */
char *my_dhm_P =
	"9CE85640903BF123906947FEDE767261" \
	"D9B4A973EB8F7D984A8C656E2BCC161C" \
	"183D4CA471BA78225F940F16D1D99CA3" \
	"E66152CC68EDCE1311A390F307741835" \
	"44FF6AB553EC7073AD0CB608F2A3B480" \
	"19E6C02BCED40BD30E91BB2469089670" \
	"DEF409C08E8AC24D1732A6128D2220DC53";
char *my_dhm_G = "4";

#ifdef USE_POLARSSL_TESTCERT
static void initTestCert()
{
	int rc;
	builtInTestCertificate = true;
#ifdef POLARSSL_API_V1_3_ABOVE
	rc = x509_crt_parse_rsa(&certificate, (unsigned char *)test_srv_crt,
		strlen(test_srv_crt));
#else
	rc = x509parse_crt(&certificate, (unsigned char *)test_srv_crt,
		strlen(test_srv_crt));
#endif
	if (rc != 0)
		Log_fatal("Could not parse built-in test certificate");
}

static void initTestKey()
{
	int rc;

	rc = x509parse_key_rsa(&key, (unsigned char *)test_srv_key,
	                       strlen(test_srv_key), NULL, 0);
	if (rc != 0)
		Log_fatal("Could not parse built-in test RSA key");
}
#endif

/*
 * How to generate a self-signed cert with openssl:
 * openssl genrsa 1024 > host.key
 * openssl req -new -x509 -nodes -sha1 -days 365 -key host.key > host.cert
 */
static void initCert()
{
	int rc;
	char *crtfile = (char *)getStrConf(CERTIFICATE);

	if (crtfile == NULL) {
#ifdef USE_POLARSSL_TESTCERT
		Log_warn("No certificate file specified. Falling back to test certificate.");
		initTestCert();
#else
		Log_fatal("No certificate file specified");
#endif
		return;
	}
#ifdef POLARSSL_API_V1_3_ABOVE
	rc = x509_crt_parse_file(&certificate, crtfile);
#else
	rc = x509parse_crtfile(&certificate, crtfile);
#endif
	if (rc != 0) {
#ifdef USE_POLARSSL_TESTCERT
		Log_warn("Could not read certificate file '%s'. Falling back to test certificate.", crtfile);
		initTestCert();
#else
		Log_fatal("Could not read certificate file '%s'", crtfile);
#endif
		return;
	}
}

static void initKey()
{
	int rc;
	char *keyfile = (char *)getStrConf(KEY);

	if (keyfile == NULL)
		Log_fatal("No key file specified");
	rc = x509parse_keyfile(&key, keyfile, NULL);
	if (rc != 0)
		Log_fatal("Could not read RSA key file %s", keyfile);
}

#ifndef USE_POLARSSL_HAVEGE
int urandom_bytes(void *ctx, unsigned char *dest, size_t len)
{
	int cur;

	while (len) {
		cur = read(urandom_fd, dest, len);
		if (cur < 0)
			continue;
		len -= cur;
	}
	return 0;
}
#endif

#define DEBUG_LEVEL 0
static void pssl_debug(void *ctx, int level, const char *str)
{
    if (level <= DEBUG_LEVEL)
		Log_info("PolarSSL [level %d]: %s", level, str);
}

void SSLi_init(void)
{
	char verstring[12];

	initCert();
#ifdef USE_POLARSSL_TESTCERT
	if (builtInTestCertificate) {
		Log_warn("*** Using built-in test certificate and RSA key ***");
		Log_warn("*** This is not secure! Please use a CA-signed certificate or create a key and self-signed certificate ***");
		initTestKey();
	}
	else
		initKey();
#else
	initKey();
#endif

	/* Initialize random number generator */
#ifdef USE_POLARSSL_HAVEGE
    havege_init(&hs);
#else
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
	    Log_fatal("Cannot open /dev/urandom");
#endif

    version_get_string(verstring);
    Log_info("PolarSSL library version %s initialized", verstring);
}

void SSLi_deinit(void)
{
#ifdef POLARSSL_API_V1_3_ABOVE
	x509_crt_free(&certificate);
#else
	x509_free(&certificate);
#endif
	rsa_free(&key);
}

/* Create SHA1 of last certificate in the peer's chain. */
bool_t SSLi_getSHA1Hash(SSL_handle_t *ssl, uint8_t *hash)
{
#ifdef POLARSSL_API_V1_3_ABOVE
	x509_crt const *cert;
#else
	x509_cert const *cert;
#endif
#ifdef POLARSSL_API_V1_2_ABOVE
	cert = ssl_get_peer_cert(ssl);
#else
	cert = ssl->peer_cert;
#endif
	if (!cert) {
		return false;
	}
	sha1(cert->raw.p, cert->raw.len, hash);
	return true;
}

SSL_handle_t *SSLi_newconnection(int *fd, bool_t *SSLready)
{
	ssl_context *ssl;
	ssl_session *ssn;
	int rc;

	ssl = malloc(sizeof(ssl_context));
	ssn = malloc(sizeof(ssl_session));
	if (!ssl || !ssn)
		Log_fatal("Out of memory");
	memset(ssl, 0, sizeof(ssl_context));
	memset(ssn, 0, sizeof(ssl_session));

	rc = ssl_init(ssl);
	if (rc != 0 )
		Log_fatal("Failed to initialize: %d", rc);

	ssl_set_endpoint(ssl, SSL_IS_SERVER);
	ssl_set_authmode(ssl, SSL_VERIFY_OPTIONAL);

#ifdef USE_POLARSSL_HAVEGE
	ssl_set_rng(ssl, HAVEGE_RAND, &hs);
#else
	ssl_set_rng(ssl, urandom_bytes, NULL);
#endif

	ssl_set_dbg(ssl, pssl_debug, NULL);
	ssl_set_bio(ssl, net_recv, fd, net_send, fd);

	ssl_set_ciphersuites(ssl, ciphers);

#ifdef POLARSSL_API_V1_2_ABOVE
    ssl_set_session(ssl, ssn);
#else
    ssl_set_session(ssl, 0, 0, ssn);
#endif

    ssl_set_ca_chain(ssl, &certificate, NULL, NULL);
#ifdef POLARSSL_API_V1_3_ABOVE
	ssl_set_own_cert_rsa(ssl, &certificate, &key);
#else
	ssl_set_own_cert(ssl, &certificate, &key);
#endif
	ssl_set_dh_param(ssl, my_dhm_P, my_dhm_G);

	return ssl;
}

int SSLi_nonblockaccept(SSL_handle_t *ssl, bool_t *SSLready)
{
	int rc;

	rc = ssl_handshake(ssl);
	if (rc != 0) {
		if (rc == POLARSSL_ERR_NET_WANT_READ || rc == POLARSSL_ERR_NET_WANT_WRITE) {
			return 0;
		} else if (rc == POLARSSL_ERR_X509_CERT_VERIFY_FAILED) { /* Allow this (selfsigned etc) */
			return 0;
		} else {
			Log_warn("SSL handshake failed: %d", rc);
			return -1;
		}
	}
	*SSLready = true;
	return 0;
}

int SSLi_read(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	int rc;

	rc = ssl_read(ssl, buf, len);
	if (rc == POLARSSL_ERR_NET_WANT_READ)
		return SSLI_ERROR_WANT_READ;
	return rc;
}

int SSLi_write(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	int rc;

	rc = ssl_write(ssl, buf, len);
	if (rc == POLARSSL_ERR_NET_WANT_WRITE)
		return SSLI_ERROR_WANT_WRITE;
	return rc;
}

int SSLi_get_error(SSL_handle_t *ssl, int code)
{
	return code;
}

bool_t SSLi_data_pending(SSL_handle_t *ssl)
{
	return ssl_get_bytes_avail(ssl) > 0;
}

void SSLi_shutdown(SSL_handle_t *ssl)
{
	ssl_close_notify(ssl);
}

void SSLi_free(SSL_handle_t *ssl)
{
	Log_debug("SSLi_free");
#if (POLARSSL_VERSION_MINOR <= 2 && POLARSSL_VERSION_PATCH < 6)
	free(ssl->session); /* Workaround for memory leak in PolarSSL < 1.2.6 */
	ssl->session = NULL;
#endif
	ssl_free(ssl);
	free(ssl);
}


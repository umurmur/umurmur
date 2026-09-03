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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include <mbedtls/psa_util.h>
#else
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
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
	MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
	MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    0
};

#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#ifdef MBEDTLS_ENTROPY_C
static mbedtls_entropy_context entropy;
#ifdef MBEDTLS_CTR_DRBG_C
static mbedtls_ctr_drbg_context ctr_drbg;
#endif
#endif
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#define UMURMUR_MBEDTLS_RNG     mbedtls_psa_get_random
#define UMURMUR_MBEDTLS_RNG_CTX MBEDTLS_PSA_RANDOM_STATE
#else
#define UMURMUR_MBEDTLS_RNG     mbedtls_ctr_drbg_random
#define UMURMUR_MBEDTLS_RNG_CTX &ctr_drbg
#endif

static mbedtls_x509_crt certificate;
static inline int x509parse_keyfile(mbedtls_pk_context *pk, const char *path, const char *pwd)
{
    int ret;

    mbedtls_pk_init(pk);
    ret = mbedtls_pk_parse_keyfile(pk, path, pwd, UMURMUR_MBEDTLS_RNG, UMURMUR_MBEDTLS_RNG_CTX);
    if (ret == 0 && !mbedtls_pk_can_do(pk, MBEDTLS_PK_ECDSA) && !mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA))
	{
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;
	}

    return ret;
}

static mbedtls_pk_context key;

#if defined(MBEDTLS_X509_CRT_WRITE_C) && defined(MBEDTLS_PK_WRITE_C) && \
	defined(MBEDTLS_PEM_WRITE_C) && defined(MBEDTLS_GENPRIME) && defined(MBEDTLS_RSA_C)
#define UMURMUR_MBEDTLS_CAN_GENCERT 1
#else
#define UMURMUR_MBEDTLS_CAN_GENCERT 0
#endif

static bool_t file_exists(const char *filename)
{
	return (access(filename, F_OK) == 0);
}

#if UMURMUR_MBEDTLS_CAN_GENCERT
static void mbedtls_fatal(const char *what, int rc)
{
	char buffer[128];
	mbedtls_strerror(rc, buffer, sizeof(buffer));
	Log_fatal("%s: %s", what, buffer);
}

static void write_pem_file(const char *path, const unsigned char *pem)
{
	FILE *fp = fopen(path, "w");
	if (fp == NULL) {
		Log_warn("Unable to open %s for writing", path);
		return;
	}
	if (fputs((const char *)pem, fp) == EOF)
		Log_warn("Unable to write %s", path);
	fclose(fp);
}

static void generate_cert_and_key(const char *keyfile, const char *crtfile)
{
	mbedtls_x509write_cert crt;
	mbedtls_rsa_context *rsa;
	unsigned char cert_pem[4096] = {0}, key_pem[4096] = {0};
	char not_before[32], not_after[32];
	time_t now;
	struct tm *tm, t;
	int rc, year;

	Log_info("Generating new server certificate.");

	mbedtls_x509write_crt_init(&crt);

	if ((rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
		goto err;
	rsa = mbedtls_pk_rsa(key);
	if (rsa == NULL) {
		rc = MBEDTLS_ERR_PK_TYPE_MISMATCH;
		goto err;
	}
	rc = mbedtls_rsa_gen_key(rsa, UMURMUR_MBEDTLS_RNG, UMURMUR_MBEDTLS_RNG_CTX, 2048, 65537);
	if (rc != 0)
		goto err;

	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
#if MBEDTLS_VERSION_NUMBER >= 0x03020000
	{
		unsigned char serial = 1;
		if ((rc = mbedtls_x509write_crt_set_serial_raw(&crt, &serial, 1)) != 0)
			goto err;
	}
#else
	{
		mbedtls_mpi serial;
		mbedtls_mpi_init(&serial);
		rc = mbedtls_mpi_lset(&serial, 1);
		if (rc == 0)
			rc = mbedtls_x509write_crt_set_serial(&crt, &serial);
		mbedtls_mpi_free(&serial);
		if (rc != 0)
			goto err;
	}
#endif

	now = time(NULL);
	tm = gmtime(&now);
	if (tm == NULL) {
		rc = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
		goto err;
	}
	t = *tm;
	if (t.tm_mon == 1 && t.tm_mday == 29)
		t.tm_mday = 28;
	year = t.tm_year + 1900;
	snprintf(not_before, sizeof(not_before), "%04d%02d%02d%02d%02d%02d",
		year, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
	snprintf(not_after, sizeof(not_after), "%04d%02d%02d%02d%02d%02d",
		year + 20, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
	if ((rc = mbedtls_x509write_crt_set_validity(&crt, not_before, not_after)) != 0)
		goto err;

	if ((rc = mbedtls_x509write_crt_set_subject_name(&crt,
			"CN=Murmur Autogenerated Certificate v2")) != 0)
		goto err;
	if ((rc = mbedtls_x509write_crt_set_issuer_name(&crt,
			"CN=Murmur Autogenerated Certificate v2")) != 0)
		goto err;
	mbedtls_x509write_crt_set_subject_key(&crt, &key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &key);
#if defined(MBEDTLS_MD_CAN_SHA256) || defined(MBEDTLS_SHA256_C)
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
#elif defined(MBEDTLS_MD_CAN_SHA1) || defined(MBEDTLS_SHA1_C)
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA1);
#else
	Log_fatal("No hash algorithm available to sign the generated certificate.");
#endif
	if ((rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, 0)) != 0)
		goto err;
#if defined(MBEDTLS_MD_CAN_SHA1)
	if ((rc = mbedtls_x509write_crt_set_subject_key_identifier(&crt)) != 0)
		goto err;
#endif

	rc = mbedtls_x509write_crt_pem(&crt, cert_pem, sizeof(cert_pem),
		UMURMUR_MBEDTLS_RNG, UMURMUR_MBEDTLS_RNG_CTX);
	if (rc != 0)
		goto err;
	if ((rc = mbedtls_pk_write_key_pem(&key, key_pem, sizeof(key_pem))) != 0)
		goto err;

	write_pem_file(crtfile, cert_pem);
	write_pem_file(keyfile, key_pem);

	if ((rc = mbedtls_x509_crt_parse(&certificate, cert_pem, strlen((char *)cert_pem) + 1)) != 0)
		goto err;

	mbedtls_x509write_crt_free(&crt);
	return;
err:
	mbedtls_x509write_crt_free(&crt);
	mbedtls_fatal("Failed to generate key and/or certificate", rc);
}
#endif /* UMURMUR_MBEDTLS_CAN_GENCERT */

static void init_rng(void)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
	psa_crypto_init();
#else
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
#endif
}

static void initCertAndKey(void)
{
	const char *crtfile = getStrConf(CERTIFICATE);
	const char *keyfile = getStrConf(KEY);
	int rc_crt, rc_key;

	if (crtfile == NULL)
		Log_fatal("No certificate file specified");
	if (keyfile == NULL)
		Log_fatal("No key file specified");

	mbedtls_x509_crt_init(&certificate);
	rc_crt = mbedtls_x509_crt_parse_file(&certificate, crtfile);
	rc_key = x509parse_keyfile(&key, keyfile, NULL);
	if (rc_crt == 0 && rc_key == 0)
		return;

	/* Do not generate new certificate if either private key or
	 * certificate file (or both) already exists, even though one
	 * (or both) of them is invalid or inaccessible. */
	if (file_exists(keyfile) || file_exists(crtfile))
		Log_fatal("Key and/or certificate file present but invalid or inaccessible. Exiting.");

	mbedtls_x509_crt_free(&certificate);
	mbedtls_pk_free(&key);
	mbedtls_x509_crt_init(&certificate);
	mbedtls_pk_init(&key);

#if UMURMUR_MBEDTLS_CAN_GENCERT
	generate_cert_and_key(keyfile, crtfile);
#else
	Log_fatal("Key and/or certificate file missing, and this Mbed TLS build cannot generate them.");
#endif
}

int urandom_bytes(void *ctx, unsigned char *dest, size_t len)
{
	(void)ctx;
	return UMURMUR_MBEDTLS_RNG(UMURMUR_MBEDTLS_RNG_CTX, dest, len);
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

	/* RNG must be ready before key parse (mbed TLS 3+) and cert generation. */
	init_rng();
	initCertAndKey();

	/* Initialize config */
	conf = Memory_safeCalloc(1, sizeof(mbedtls_ssl_config));

	if (!conf)
		Log_fatal("Out of memory");

	mbedtls_ssl_config_init(conf);

	if((rc = mbedtls_ssl_config_defaults(conf,
			MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
		Log_fatal("mbedtls_ssl_config_defaults returned %d", rc);

	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(conf, urandom_bytes, NULL);
	mbedtls_ssl_conf_dbg(conf, pssl_debug, NULL);

	mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	mbedtls_ssl_conf_ciphersuites(conf, (const int*)&ciphers);

	mbedtls_ssl_conf_ca_chain(conf, &certificate, NULL);

	if((rc = mbedtls_ssl_conf_own_cert(conf, &certificate, &key)) != 0)
		Log_fatal("mbedtls_ssl_conf_own_cert returned %d", rc);

	Log_info("Mbed TLS library initialized (version: %s)", MBEDTLS_VERSION_STRING);
}

void SSLi_deinit(void)
{
	mbedtls_ssl_config_free(conf);
	free(conf);
	mbedtls_x509_crt_free(&certificate);
	mbedtls_pk_free(&key);
	
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#endif
}

bool_t SSLi_getSHA1Hash(SSL_handle_t *ssl, uint8_t *hash)
{
	mbedtls_x509_crt const *cert;
	cert = mbedtls_ssl_get_peer_cert(ssl);

	if (!cert) {
		return false;
	}
#if MBEDTLS_VERSION_NUMBER < 0x02070000L
	mbedtls_sha1(cert->raw.p, cert->raw.len, hash);
#elif MBEDTLS_VERSION_NUMBER < 0x03000000L
	mbedtls_sha1_ret(cert->raw.p, cert->raw.len, hash);
#elif !defined(MBEDTLS_USE_PSA_CRYPTO)
	mbedtls_sha1(cert->raw.p, cert->raw.len, hash);
#else
	size_t hash_length;
	mbedtls_psa_hash_compute(
		PSA_ALG_SHA_1, cert->raw.p, cert->raw.len, hash,
		20 /* client_t member uint8_t hash[20] */, &hash_length);
#endif
	return true;
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

	if((rc = mbedtls_ssl_setup(ssl, conf)) != 0)
		Log_fatal("mbedtls_ssl_setup returned %d", rc);

	return ssl;
}

int SSLi_nonblockaccept(SSL_handle_t *ssl, bool_t *SSLready)
{
	int rc;

	rc = mbedtls_ssl_handshake(ssl);
	if (rc != 0) {
		if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
			return 0;
		} else if (rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) { /* Allow this (selfsigned etc) */
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


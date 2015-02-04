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
#include <stdlib.h>
#include <fcntl.h>

#include "conf.h"
#include "log.h"
#include "ssl.h"

/*
 * OpenSSL interface
 */

#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
static X509 *x509;
static RSA *rsa;
static SSL_CTX *context;
static EVP_PKEY *pkey;

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

static int SSL_add_ext(X509 * crt, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, crt, crt, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(crt, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

static X509 *SSL_readcert(char *certfile)
{
	FILE *fp;
	X509 *x509;

	/* open the certificate file */
	fp = fopen(certfile, "r");
	if (fp == NULL) {
		Log_warn("Unable to open the X509 file %s for reading.", certfile);
		return NULL;
	}

	/* allocate memory for the cert structure */
	x509 = X509_new();

	if (PEM_read_X509(fp, &x509, NULL, NULL) == 0) {
		/* error reading the x509 information - check the error stack */
		Log_warn("Error trying to read X509 info.");
		fclose(fp);
		X509_free(x509);
		return NULL;
	}
	fclose(fp);
	return x509;
}

static RSA *SSL_readprivatekey(char *keyfile)
{
	FILE *fp;
	RSA *rsa;

/* open the private key file for reading */
	fp = fopen(keyfile, "r");
	if (fp == NULL) {
		Log_warn("Unable to open the private key file %s for reading.", keyfile);
		return NULL;
	}

/* allocate memory for the RSA structure */
	rsa = RSA_new();

	/* assign a callback function for the password */

	/* read a private key from file */
	if (PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL) <= 0) {
		/* error reading the key - check the error stack */
		Log_warn("Error trying to read private key.");
		RSA_free(rsa);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	return rsa;
}

static void SSL_writecert(char *certfile, X509 *x509)
{
	FILE *fp;

	/* open the private key file */
	fp = fopen(certfile, "w");
	if (fp == NULL) {
		Log_warn("Unable to open the X509 file %s for writing", certfile);
		return;
	}
	if (PEM_write_X509(fp, x509) == 0) {
		Log_warn("Error trying to write X509 info.");
	}
	fclose(fp);
}

static void SSL_writekey(char *keyfile, RSA *rsa)
{
	FILE *fp;

	/* open the private key file for reading */
	fp = fopen(keyfile, "w");
	if (fp == NULL) {
		Log_warn("Unable to open the private key file %s for writing.", keyfile);
		return;
	}

	if (PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL) == 0) {
		Log_warn("Error trying to write private key");
	}
	fclose(fp);
}

static void SSL_initializeCert() {

	char *crt, *key, *pass;

	crt = (char *)getStrConf(CERTIFICATE);
	key = (char *)getStrConf(KEY);
	pass = (char *)getStrConf(PASSPHRASE);

	x509 = SSL_readcert(crt);
	rsa = SSL_readprivatekey(key);
	if (rsa != NULL) {
		pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(pkey, rsa);
	}


#if 0
	/* Later ... */
	if (key && !x509) {
		qscCert = QSslCertificate(key);
		if (! qscCert.isNull()) {
			logthis("Using certificate from key.");
		}
	}

	if (! qscCert.isNull()) {
		QSsl::KeyAlgorithm alg = qscCert.publicKey().algorithm();
		/* Fetch algorith from cert */
		if (! key.isEmpty()) {
			/* get key */
			qskKey = QSslKey(key, alg, QSsl::Pem, QSsl::PrivateKey, pass);
			if (qskKey.isNull()) {
				logthis("Failed to parse key.");
			}
		}

		if (! crt.isEmpty() && qskKey.isNull()) {
			/* get key from certificate */
			qskKey = QSslKey(crt, alg, QSsl::Pem, QSsl::PrivateKey, pass);
			if (! qskKey.isNull()) {
				logthis("Using key from certificate.");
			}
		}

	}
#endif

	if (!rsa || !x509) {
		Log_info("Generating new server certificate.");


		CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

		x509 = X509_new();
		pkey = EVP_PKEY_new();
		rsa = RSA_generate_key(1024,RSA_F4,NULL,NULL);
		EVP_PKEY_assign_RSA(pkey, rsa);

		X509_set_version(x509, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x509),1);
		X509_gmtime_adj(X509_get_notBefore(x509),0);
		X509_gmtime_adj(X509_get_notAfter(x509),60*60*24*365);
		X509_set_pubkey(x509, pkey);

		X509_NAME *name=X509_get_subject_name(x509);

		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const uint8_t *)"Murmur Autogenerated Certificate v2", -1, -1, 0);
		X509_set_issuer_name(x509, name);
		SSL_add_ext(x509, NID_basic_constraints, "critical,CA:FALSE");
		SSL_add_ext(x509, NID_ext_key_usage, "serverAuth,clientAuth");
		SSL_add_ext(x509, NID_subject_key_identifier, "hash");
		SSL_add_ext(x509, NID_netscape_comment, "Generated from umurmur");

		X509_sign(x509, pkey, EVP_md5());

		SSL_writecert(crt, x509);
		SSL_writekey(key, rsa);
	}

}

void SSLi_init(void)
{
	const SSL_METHOD *method;
	SSL *ssl;
	int i, offset = 0, cipherstringlen = 0;
	STACK_OF(SSL_CIPHER) *cipherlist = NULL, *cipherlist_new = NULL;
	SSL_CIPHER *cipher;
	char *cipherstring, tempstring[128];

	SSL_library_init();
	OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
	SSL_load_error_strings();			/* load all error messages */
	ERR_load_crypto_strings();			/* load all error messages */
	method = SSLv23_server_method();		/* create new server-method instance */
	context = SSL_CTX_new(method);			/* create new context from method */
	if (context == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	char* sslCAPath = getStrConf(CAPATH);
	if(sslCAPath != NULL)
	{
		SSL_CTX_load_verify_locations(context, NULL, sslCAPath);
	}

	SSL_initializeCert();
	if (SSL_CTX_use_certificate(context, x509) <= 0)
		Log_fatal("Failed to initialize cert");
	if (SSL_CTX_use_PrivateKey(context, pkey) <= 0) {
		ERR_print_errors_fp(stderr);
		Log_fatal("Failed to initialize private key");
	}

	/* Set cipher list */
	ssl = SSL_new(context);
	cipherlist = (STACK_OF(SSL_CIPHER) *) SSL_get_ciphers(ssl);
	cipherlist_new = (STACK_OF(SSL_CIPHER) *) sk_SSL_CIPHER_new_null();

	for ( i = 0; (cipher = sk_SSL_CIPHER_value(cipherlist, i)) != NULL; i++) {
		if (SSL_CIPHER_get_bits(cipher, NULL) >= 128) {
			sk_SSL_CIPHER_push(cipherlist_new, cipher);
		}
	}
	Log_debug("List of ciphers:");
	if (cipherlist_new) {
		for (i = 0; (cipher = sk_SSL_CIPHER_value(cipherlist_new, i)) != NULL; i++) {
			Log_debug("%s", SSL_CIPHER_get_name(cipher));
			cipherstringlen += strlen(SSL_CIPHER_get_name(cipher)) + 1;
		}
		cipherstring = malloc(cipherstringlen + 1);
		if (cipherstring == NULL)
			Log_fatal("Out of memory");
		for (i = 0; (cipher = sk_SSL_CIPHER_value(cipherlist_new, i)) != NULL; i++) {
			offset += sprintf(cipherstring + offset, "%s:", SSL_CIPHER_get_name(cipher));
		}
	}

	if (cipherlist_new)
		sk_SSL_CIPHER_free(cipherlist_new);

	if (strlen(cipherstring) == 0)
		Log_fatal("No suitable ciphers found!");

	if (SSL_CTX_set_cipher_list(context, cipherstring) == 0)
		Log_fatal("Failed to set cipher list!");

	free(cipherstring);

	SSL_CTX_set_verify(context, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE,
	                   verify_callback);

	SSL_free(ssl);
	Log_info("OpenSSL library initialized");

}

void SSLi_deinit(void)
{
	SSL_CTX_free(context);
	EVP_cleanup();
}

int SSLi_nonblockaccept(SSL_handle_t *ssl, bool_t *SSLready)
{
	int rc;
	rc = SSL_accept(ssl);
	if (rc < 0) {
		if (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ ||
			SSL_get_error(ssl, rc) == SSL_ERROR_WANT_WRITE) {
			Log_debug("SSL not ready");
			return 0;
		} else {
			Log_warn("SSL error: %s", ERR_error_string(SSL_get_error(ssl, rc), NULL));
			return -1;
		}
	}
	*SSLready = true;
	return 0;
}

SSL_handle_t *SSLi_newconnection(int *fd, bool_t *SSLready)
{
	SSL *ssl;

	*SSLready = false;
	ssl = SSL_new(context);
	SSL_set_fd(ssl, *fd);
	if (SSLi_nonblockaccept(ssl, SSLready) < 0) {
		SSL_free(ssl);
		return NULL;
	}
	return ssl;
}

/* Create SHA1 of last certificate in the peer's chain. */
bool_t SSLi_getSHA1Hash(SSL_handle_t *ssl, uint8_t *hash)
{
	X509 *x509;
	uint8_t *buf, *p;
	int len;

	x509 = SSL_get_peer_certificate(ssl);
	if (!x509) {
		return false;
	}

	len = i2d_X509(x509, NULL);
	buf = malloc(len);
	if (buf == NULL) {
		Log_fatal("malloc");
	}

	p = buf;
	i2d_X509(x509, &p);

	SHA1(buf, len, hash);
	free(buf);
	return true;
}

void SSLi_closeconnection(SSL_handle_t *ssl)
{
	SSL_free(ssl);
}

void SSLi_shutdown(SSL_handle_t *ssl)
{
	SSL_shutdown(ssl);
}

int SSLi_read(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	return SSL_read(ssl, buf, len);
}

int SSLi_write(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	return SSL_write(ssl, buf, len);
}

int SSLi_get_error(SSL_handle_t *ssl, int code)
{
	return SSL_get_error(ssl, code);
}

bool_t SSLi_data_pending(SSL_handle_t *ssl)
{
	return SSL_pending(ssl);
}

void SSLi_free(SSL_handle_t *ssl)
{
	SSL_free(ssl);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	char    buf[256];
	X509   *err_cert;
	int     err, depth;
	SSL    *ssl;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    if (depth > 5) {
        preverify_ok = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }
    if (!preverify_ok) {
	    Log_warn("SSL: verify error:num=%d:%s:depth=%d:%s\n", err,
	             X509_verify_cert_error_string(err), depth, buf);
    }
    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
	    X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	    Log_warn("issuer= %s", buf);
    }
    return 1;
}

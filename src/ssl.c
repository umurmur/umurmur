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
#include <string.h>
#include <stdlib.h>

#include "conf.h"
#include "log.h"
#include "ssl.h"

#ifdef USE_POLARSSL
/*
 * PolarSSL interface
 */

#include <polarssl/havege.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/ssl.h>
#include <polarssl/net.h>

#define CA_CRT_FILENAME "ca.crt"

int ciphers[] =
{
    SSL_EDH_RSA_AES_256_SHA,
    SSL_EDH_RSA_CAMELLIA_256_SHA,
    SSL_EDH_RSA_DES_168_SHA,
    SSL_RSA_AES_256_SHA,
    SSL_RSA_CAMELLIA_256_SHA,
    SSL_RSA_AES_128_SHA,
    SSL_RSA_CAMELLIA_128_SHA,
    SSL_RSA_DES_168_SHA,
    SSL_RSA_RC4_128_SHA,
    SSL_RSA_RC4_128_MD5,
    0
};
static x509_cert certificate;
static rsa_context key;
bool_t builtInTestCertificate;

havege_state hs; /* exported to crypt.c */

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

static void initTestCert()
{
	int rc;
	builtInTestCertificate = true;
	rc = x509parse_crt(&certificate, (unsigned char *)test_srv_crt,
					   strlen(test_srv_crt));	
	if (rc != 0)
		Log_fatal("Could not parse built-in test certificate");
	rc = x509parse_crt(&certificate, (unsigned char *)test_ca_crt,
					   strlen(test_ca_crt));
	if (rc != 0)
		Log_fatal("Could not parse built-in test CA certificate");
}

static void initTestKey()
{
	int rc;
	
	rc = x509parse_key(&key, (unsigned char *)test_srv_key,
					   strlen(test_srv_key), NULL, 0);
	if (rc != 0)
		Log_fatal("Could not parse built-in test RSA key");
}

/*
 * openssl genrsa 1024 > host.key
 * openssl req -new -x509 -nodes -sha1 -days 365 -key host.key > host.cert
 */
static void initCert()
{
	int rc;
	char *crtfile = (char *)getStrConf(CERTIFICATE);
	char *ca_file, *p;
	
	if (crtfile == NULL) {
		Log_warn("No certificate file specified");
		initTestCert();
		return;
	}
	rc = x509parse_crtfile(&certificate, crtfile);
	if (rc != 0) {
		Log_warn("Could not read certificate file %s", crtfile);
		initTestCert();
		return;
	}
	
	/* Look for CA certificate file in same dir */
	ca_file = malloc(strlen(crtfile) + strlen(CA_CRT_FILENAME) + 1);
	strcpy(ca_file, crtfile);
	p = strrchr(ca_file, '/');
	if (p != NULL)
		strcpy(p + 1, CA_CRT_FILENAME);
	else
		strcpy(ca_file, CA_CRT_FILENAME);
	
	rc = x509parse_crtfile(&certificate, ca_file);
	if (rc != 0) { /* No CA certifiacte found. Assume self-signed. */
		Log_info("CA certificate file %s not found. Assuming self-signed certificate.", ca_file);
		/*
		 * Apparently PolarSSL needs to read something more into certificate chain.
		 * Doesn't seem to matter what. Read own certificate again.
		 */
		rc = x509parse_crtfile(&certificate, crtfile);
		if (rc != 0)
			Log_fatal("Could not read certificate file %s", crtfile);
	}
	free(ca_file);
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

#define DEBUG_LEVEL 0
static void pssl_debug(void *ctx, int level, char *str)
{
    if (level <= DEBUG_LEVEL)
		Log_debug("PolarSSL [level %d]: %s", level, str);
}

void SSLi_init(void)
{
	initCert();
	if (builtInTestCertificate) {
		Log_warn("*** Using built-in test certificate and RSA key ***");
		Log_warn("*** This is not secure! Please use a CA-signed certificate or create a self-signed certificate ***");
		initTestKey();
	}
	else
		initKey();
    havege_init(&hs);
	Log_info("PolarSSL library initialized");
}

void SSLi_deinit(void)
{
	x509_free(&certificate);
	rsa_free(&key);
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
		Log_fatal("Failed to initalize: %d", rc);
	
	ssl_set_endpoint(ssl, SSL_IS_SERVER);	
    ssl_set_authmode(ssl, SSL_VERIFY_OPTIONAL);

    ssl_set_rng(ssl, havege_rand, &hs);
    ssl_set_dbg(ssl, pssl_debug, NULL);
    ssl_set_bio(ssl, net_recv, fd, net_send, fd);

    ssl_set_ciphers(ssl, ciphers);
    ssl_set_session(ssl, 0, 0, ssn);

    ssl_set_ca_chain(ssl, certificate.next, NULL, NULL);
    ssl_set_own_cert(ssl, &certificate, &key);
    ssl_set_dh_param(ssl, my_dhm_P, my_dhm_G);

	return ssl;
}

int SSLi_nonblockaccept(SSL_handle_t *ssl, bool_t *SSLready)
{
	int rc;
	
	rc = ssl_handshake(ssl);
	if (rc != 0) {
		if (rc == POLARSSL_ERR_NET_TRY_AGAIN) {
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
	if (rc == POLARSSL_ERR_NET_TRY_AGAIN)
		return SSLI_ERROR_WANT_READ;
	return rc;
}

int SSLi_write(SSL_handle_t *ssl, uint8_t *buf, int len)
{
	int rc;
	rc = ssl_write(ssl, buf, len);
	if (rc == POLARSSL_ERR_NET_TRY_AGAIN)
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
	free(ssl->session); /* XXX - Hmmm. */
	ssl_free(ssl);
	free(ssl);
}

#else
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
			
	/* open the private key file */
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
	BIO *err_output;
	
	/* prepare a BIO for outputting error messages */
	
	err_output = BIO_new_fp(stderr,BIO_NOCLOSE);
	
	/* open the private key file */
	fp = fopen(certfile, "w");
	if (fp == NULL) {
		BIO_printf(err_output, "Unable to open the X509 file for writing.\n");
		BIO_free(err_output);
		return;
	}
		
	if (PEM_write_X509(fp, x509) == 0) {
		BIO_printf(err_output, "Error trying to write X509 info.\n");
		ERR_print_errors(err_output);
	}
	fclose(fp);
}

static void SSL_writekey(char *keyfile, RSA *rsa)
{
	FILE *fp;
	BIO *err_output;
	/* prepare a BIO for outputing error messages */	
	err_output = BIO_new_fp(stderr, BIO_NOCLOSE);
	
	/* open the private key file for reading */
	fp = fopen(keyfile, "w");
	if (fp == NULL) {
		BIO_printf(err_output, "Unable to open the private key file %s for writing.\n", keyfile);
		BIO_free(err_output);
		return;
	}
	
	if (PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL) == 0) {
		/* error reading the key - check the error stack */
		BIO_printf(err_output, "Error trying to write private key\n");
		ERR_print_errors(err_output);
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
		logthis("Generating new server certificate.");

		BIO *bio_err;
		
		CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
		
		bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
		
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
	int i, offset = 0;
	STACK_OF(SSL_CIPHER) *cipherlist = NULL, *cipherlist_new = NULL;
	SSL_CIPHER *cipher;
	char cipherstring[1024];
		
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
		for ( i = 0; (cipher = sk_SSL_CIPHER_value(cipherlist_new, i)) != NULL; i++) {
			Log_debug("%s", SSL_CIPHER_get_name(cipher));
			offset += snprintf(cipherstring + offset, 1024 - offset, "%s:", SSL_CIPHER_get_name(cipher));
		}
		cipherstring[offset - 1] = '\0';
	}
	
	if (cipherlist_new)
		sk_SSL_CIPHER_free(cipherlist_new);
	
	if (strlen(cipherstring) == 0)
		Log_fatal("No suitable ciphers found!");
	
	if (SSL_CTX_set_cipher_list(context, cipherstring) == 0)
		Log_fatal("Failed to set cipher list!");
		
	
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

#endif

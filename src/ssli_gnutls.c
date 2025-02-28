/* Copyright (C) 2015-2016, Felix Morgner <felix.morgner@gmail.com>

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

#include "ssl.h"
#include "conf.h"
#include "log.h"
#include "memory.h"

#include <stdlib.h>

static gnutls_dh_params_t dhParameters;
static gnutls_certificate_credentials_t certificate;

static const char * ciphers = "NONE:"
							  "+ECDHE-ECDSA:+ECDHE-RSA:+RSA:"
							  "+AES-256-GCM:+AES-128-GCM:"
							  "+AEAD:+SHA384:+SHA256:+SHA1:"
							  "+CURVE-ALL:"
							  "+COMP-NULL:"
							  "+SIGN-ALL:"
							  "+VERS-TLS1.2:+VERS-TLS1.0:"
							  "+CTYPE-X509";

static gnutls_priority_t cipherCache;

void initializeCertificate()
{
	char* certificatePath = (char*) getStrConf(CERTIFICATE);

	if(!certificatePath) {
		Log_fatal("No certificate file specified.");
	}

	char* keyPath = (char*) getStrConf(KEY);

	if(!keyPath) {
		Log_fatal("No key file specified");
	}

	gnutls_certificate_allocate_credentials(&certificate);

	int error = gnutls_certificate_set_x509_key_file(certificate, certificatePath, keyPath, GNUTLS_X509_FMT_PEM);

	if( error != GNUTLS_E_SUCCESS ) {
		Log_fatal("Could not open key (%s) or certificate (%s).", keyPath, certificatePath);
	}
}

void SSLi_init()
{
	if(gnutls_priority_init(&cipherCache, ciphers, NULL) != GNUTLS_E_SUCCESS)
	{
		Log_fatal("Failed to set priorities");
	}

	initializeCertificate();

	Log_info("GnuTLS library initialized (version: %s)", gnutls_check_version(NULL));
}

void SSLi_deinit()
{
	gnutls_certificate_free_credentials(certificate);
	gnutls_priority_deinit(cipherCache);
	gnutls_global_deinit();
}

SSL_handle_t * SSLi_newconnection( int * fileDescriptor, bool_t * isSSLReady )
{
	gnutls_session_t * session
		= Memory_safeCalloc(1, sizeof(gnutls_session_t));

	gnutls_init(session, GNUTLS_SERVER);
	gnutls_priority_set(*session, cipherCache);
	gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, certificate);

	gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUIRE);

	gnutls_transport_set_int(*session, *fileDescriptor);

	if(isSSLReady && SSLi_nonblockaccept(session, isSSLReady))
		*isSSLReady = true;

	return session;
}

bool_t SSLi_getSHA1Hash(SSL_handle_t *session, uint8_t *hash)
{
	gnutls_datum_t const * certificateData = gnutls_certificate_get_peers(*session, NULL);

	size_t resultSize = 0;
	int error = gnutls_fingerprint( GNUTLS_DIG_SHA1, certificateData, hash, &resultSize);
	return error == GNUTLS_E_SUCCESS && resultSize == 20;
}

int SSLi_nonblockaccept( SSL_handle_t *session, bool_t * isSSLReady )
{
	int error;
	do {
		error = gnutls_handshake(*session);
	} while(error < GNUTLS_E_SUCCESS && !gnutls_error_is_fatal(error));

	if ( error < GNUTLS_E_SUCCESS ) {
		Log_warn("TLS handshake failed with error %i (%s).", error, gnutls_strerror(error));
	}

	if(isSSLReady)
		*isSSLReady = true;

	return error;
}

int SSLi_read(SSL_handle_t *session, uint8_t *buffer, int length)
{
	return gnutls_record_recv(*session, buffer, length);
}

int SSLi_write(SSL_handle_t *session, uint8_t *buffer, int length)
{
	return gnutls_record_send(*session, buffer, length);
}

int SSLi_get_error(SSL_handle_t *session, int code)
{
	return code;
}

bool_t SSLi_data_pending(SSL_handle_t *session)
{
	return gnutls_record_check_pending(*session);
}

void SSLi_shutdown(SSL_handle_t *session)
{
	gnutls_bye(*session, GNUTLS_SHUT_WR);
}

void SSLi_free(SSL_handle_t *session)
{
	gnutls_deinit(*session);
	free(session);
}

#include "ssl.h"
#include "conf.h"
#include "log.h"

static gnutls_dh_params_t dhParameters;
static gnutls_certificate_credentials_t certificate;

static const char * ciphers = "NONE:+CTYPE-X.509:+DHE-RSA:+RSA:+AES-256-CBC:+AES-128-CBC:+SHA256:+SHA1:+VERS-TLS-ALL:+COMP-ALL:+SIGN-DSA-SHA256:+SIGN-DSA-SHA1";
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
  unsigned const bitCount = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_MEDIUM);

  gnutls_dh_params_init(&dhParameters);
  gnutls_dh_params_generate2(dhParameters, bitCount);

#if GNUTLS_VERSION_NUMBER < 0x030300
  gnutls_global_init();
#endif

  gnutls_priority_init(&cipherCache, ciphers, NULL);

  initializeCertificate();

  Log_info("Sucessfully initialized GNUTLS version %s", gnutls_check_version(NULL));

  }

void SSLi_deinit()
  {
  gnutls_certificate_free_credentials(certificate);
  gnutls_priority_deinit(cipherCache);
  gnutls_global_deinit();
  }

SSL_handle_t * SSLi_newconnection( int * fileDescriptor, bool_t * isSSLReady )
  {
  gnutls_session_t * session = calloc(1, sizeof(gnutls_session_t));

  gnutls_init(session, GNUTLS_SERVER);
  gnutls_priority_set(*session, cipherCache);
  gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, certificate);

  gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUIRE);

  gnutls_transport_set_int(*session, *fileDescriptor);

  if(isSSLReady && SSLi_nonblockaccept(session, isSSLReady))
    *isSSLReady = true;

  return session;
  }

bool_t SSLi_getSHA1Hash(SSL_handle_t *ssl, uint8_t *hash)
  {
  *hash = 0;
  return true;
  }

int SSLi_nonblockaccept( SSL_handle_t *session, bool_t * isSSLReady )
  {
  int error;
  do {
    error = gnutls_handshake(*session);
  } while(error < GNUTLS_E_SUCCESS && !gnutls_error_is_fatal(error));

  if ( error < GNUTLS_E_SUCCESS ) {
    Log_fatal("TLS handshake failed with error %i (%s).", error, gnutls_strerror(error));
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
  }

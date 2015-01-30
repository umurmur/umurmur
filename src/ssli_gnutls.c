#include "ssl.h"
#include "conf.h"
#include "log.h"

static gnutls_dh_params_t dhParameters;
static gnutls_certificate_credentials_t certificate;

static const char * ciphers = "SECURE128:-VERS-DTLS-ALL:-VERS-SSL3.0:-VERS-TLS1.0:+COMP_ALL";
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
  gnutls_session_t * session; // Maybe we need to calloc here

  gnutls_init(session, GNUTLS_SERVER);
  gnutls_priority_set(*session, cipherCache);
  gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, certificate);

  gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUIRE);

  gnutls_transport_set_int(*session, *fileDescriptor);

  int error;
  do {
  gnutls_handshake(*session);
  } while(error < GNUTLS_E_SUCCESS && !gnutls_error_is_fatal(error));

  if ( error < GNUTLS_E_SUCCESS ) {
    Log_fatal("TLS handshake failed with error %i (%s).", error, gnutls_strerror(error));
  }

  return session;
  }


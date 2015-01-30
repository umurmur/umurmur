#include "ssl.h"
#include "conf.h"

static gnutls_dh_params_t dhParameters;
static gnutls_certificate_credentials certificate;

void initiliazeCertificate()
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

  initializeCertificate();

  Log_info("Sucessfully initialized GNUTLS version %s", gnutls_check_version(NULL));

  }


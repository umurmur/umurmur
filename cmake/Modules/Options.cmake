# PolarSSL
option(USE_POLARSSL_TESTCERT "Link to the PolarSSL test certificate and key." OFF)
option(USE_POLARSSL_HAVEGE "Use the PolarSSL HAVEGE random generator key." OFF)

if(USE_POLARSSL_TESTCERT OR USE_POLARSSL_HAVEGE)
  if(SSL NOT MATCHES "polarssl")
    message(FATAL_ERROR "Selecting USE_POLARSSL_TESTCERT or USE_POLARSSL_HAVEGE implies SSL=polarssl")
  endif()
endif()

# mbedTLS
option(USE_MBEDTLS_TESTCERT "Link to the mbedTLS test certificate and key." OFF)
option(USE_MBEDTLS_HAVEGE "Use the mbedTLS HAVEGE random generator key." OFF)

if(USE_MBEDTLS_TESTCERT OR USE_MBEDTLS_HAVEGE)
  if(SSL NOT MATCHES "mbedtls")
    message(FATAL_ERROR "Selecting USE_MBEDTLS_TESTCERT or USE_MBEDTLS_HAVEGE implies SSL=mbedtls")
  endif()
endif()

# SHM API
option(USE_SHAREDMEMORY_API "Compile with Sharedmemory API support" OFF)


# SSL backend select

set(SSL "openssl" CACHE STRING "TLS Backend.")
set_property(CACHE SSL PROPERTY STRINGS "openssl" "mbedtls" "gnutls")

# mbedTLS
option(USE_MBEDTLS_TESTCERT "Link to the mbedTLS test certificate and key." OFF)

if(USE_MBEDTLS_TESTCERT)
  if(NOT SSL MATCHES "mbedtls")
    message(FATAL_ERROR "Selecting USE_MBEDTLS_TESTCERT implies SSL=mbedtls")
  endif()
endif()

# SHM API
option(USE_SHAREDMEMORY_API "Compile with Sharedmemory API support" OFF)


# mbedTLS
option(USE_MBEDTLS_TESTCERT "Link to the mbedTLS test certificate and key." OFF)
option(USE_MBEDTLS_HAVEGE "Use the mbedTLS HAVEGE random generator key." OFF)

if(USE_MBEDTLS_TESTCERT OR USE_MBEDTLS_HAVEGE)
  if(NOT SSL MATCHES "mbedtls")
    message(FATAL_ERROR "Selecting USE_MBEDTLS_TESTCERT or USE_MBEDTLS_HAVEGE implies SSL=mbedtls")
  endif()
endif()

# SHM API
option(USE_SHAREDMEMORY_API "Compile with Sharedmemory API support" OFF)


function(SelectTLSBackend SSL)
  # Default to OpenSSL if not specified
  if("${SSL}" STREQUAL "")
    set(SSL "openssl")
  endif()

  set(LIBRARIES "")
  set(INCLUDE_DIR "")
  set(LIBRARY_DIR "")
  # Prevent stale TLS backend state from leaking between reconfigures
  set(USE_MBEDTLS OFF PARENT_SCOPE)
  set(USE_MBEDTLS4 OFF PARENT_SCOPE)
  set(USE_GNUTLS OFF PARENT_SCOPE)

  if("${SSL}" STREQUAL "openssl")
    find_package(OpenSSL REQUIRED)
    set(SSLIMP_VERSION "OpenSSL ${OPENSSL_VERSION}")

    set(LIBRARIES OpenSSL::SSL)

    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations" PARENT_SCOPE)
    endif()

  elseif("${SSL}" STREQUAL "mbedtls")
    unset(MbedTLS_SLOT CACHE)
    find_package(MbedTLS REQUIRED)

    set(SSLIMP_VERSION "MbedTLS ${MbedTLS_VERSION}")
    set(USE_MBEDTLS ON PARENT_SCOPE)
    if(MbedTLS_VERSION VERSION_GREATER_EQUAL "4.0.0")
      set(USE_MBEDTLS4 ON PARENT_SCOPE)
    endif()
    set(LIBRARIES MbedTLS::mbedtls)

  elseif("${SSL}" STREQUAL "mbedtls3")
    set(MbedTLS_SLOT "mbedtls3" CACHE STRING "mbedTLS ABI slot directory" FORCE)
    find_package(MbedTLS 3 REQUIRED)
    if(MbedTLS_VERSION VERSION_GREATER_EQUAL "4.0.0")
      message(FATAL_ERROR "SSL=mbedtls3 requires Mbed TLS 3.x (found ${MbedTLS_VERSION})")
    endif()

    set(SSLIMP_VERSION "MbedTLS ${MbedTLS_VERSION}")
    set(USE_MBEDTLS ON PARENT_SCOPE)
    set(LIBRARIES MbedTLS::mbedtls)

  elseif("${SSL}" STREQUAL "mbedtls4")
    unset(MbedTLS_SLOT CACHE)
    find_package(MbedTLS 4 REQUIRED)

    set(SSLIMP_VERSION "MbedTLS ${MbedTLS_VERSION}")
    set(USE_MBEDTLS ON PARENT_SCOPE)
    set(USE_MBEDTLS4 ON PARENT_SCOPE)
    set(LIBRARIES MbedTLS::mbedtls)

  elseif("${SSL}" STREQUAL "gnutls")
    find_package(GnuTLS 3 REQUIRED)
    # Nettle is the primary and required crypto library for GnuTLS
    find_package(Nettle REQUIRED)

    set(SSLIMP_VERSION "GnuTLS ${GNUTLS_VERSION}")

    set(USE_GNUTLS ON PARENT_SCOPE)
    set(LIBRARIES GnuTLS::GnuTLS ${NETTLE_LIBRARIES})

  else()
    message(FATAL_ERROR "Unknown SSL backend: ${SSL}")
  endif()

  set(SSLIMP_LIBRARIES ${LIBRARIES} PARENT_SCOPE)
  set(SSLIMP_LIBRARY_DIR ${LIBRARY_DIR} PARENT_SCOPE)
  set(SSLIMP_INCLUDE_DIR ${INCLUDE_DIR} PARENT_SCOPE)
  set(SSLIMP_VERSION "${SSLIMP_VERSION}" PARENT_SCOPE)

  message(STATUS "Using ${SSLIMP_VERSION} as SSL backend")

endfunction()

function(SelectTLSBackend SSL)
  # Default to OpenSSL if not specified
  if("${SSL}" STREQUAL "")
    set(SSL "openssl")
  endif()

  set(LIBRARIES "")
  set(INCLUDE_DIR "")
  set(LIBRARY_DIR "")

  if("${SSL}" STREQUAL "openssl")
    find_package(OpenSSL REQUIRED)
    set(SSL_VERSION "OpenSSL ${OPENSSL_VERSION}")

    set(LIBRARIES OpenSSL::SSL)

    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations" PARENT_SCOPE)
    endif()

  elseif("${SSL}" STREQUAL "mbedtls")
    find_package(MbedTLS 3.6 REQUIRED)
    set(SSL_VERSION "MbedTLS ${MbedTLS_VERSION}")

    set(USE_MBEDTLS ON PARENT_SCOPE)
    set(LIBRARIES MbedTLS::mbedtls)

  elseif("${SSL}" STREQUAL "gnutls")
    find_package(GnuTLS 3 REQUIRED)
    # Nettle is the primary and required crypto library for GnuTLS
    find_package(Nettle REQUIRED)

    set(SSL_VERSION "GnuTLS ${GNUTLS_VERSION}")

    set(USE_GNUTLS ON PARENT_SCOPE)
    set(LIBRARIES GnuTLS::GnuTLS ${NETTLE_LIBRARIES})

  endif()

  set(SSLIMP_LIBRARIES ${LIBRARIES} PARENT_SCOPE)
  set(SSLIMP_LIBRARY_DIR ${LIBRARY_DIR} PARENT_SCOPE)
  set(SSLIMP_INCLUDE_DIR ${INCLUDE_DIR} PARENT_SCOPE)

  message(STATUS "Using ${SSL_VERSION} as SSL backend")

endfunction()

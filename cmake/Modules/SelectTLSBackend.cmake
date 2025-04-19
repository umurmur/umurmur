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
    set(SSL_VERSION "OpenSSL ${_OPENSSL_VERSION}")

    if(OPENSSL_FOUND)
      set(LIBRARIES ${OPENSSL_LIBRARIES})
      set(INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
      set(LIBRARY_DIR ${OPENSSL_LIB_DIR})

      if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations" PARENT_SCOPE)
      endif()
    endif()

  elseif("${SSL}" STREQUAL "mbedtls")
    find_package(mbedTLS REQUIRED)
    set(SSL_VERSION "Mbed TLS ${MBEDTLS_VERSION}")

    if(MBEDTLS_FOUND)
      set(USE_MBEDTLS ON PARENT_SCOPE)

      set(LIBRARIES ${MBEDTLS_LIBRARIES})
      set(INCLUDE_DIR ${MBEDTLS_INCLUDE_DIR})
      set(LIBRARY_DIR ${MBEDTLS_LIB_DIR})
    endif()

  elseif("${SSL}" STREQUAL "gnutls")
    find_package(GnuTLS 3 REQUIRED)
    set(SSL_VERSION "GnuTLS ${GNUTLS_VERSION}")

    if(GNUTLS_FOUND)
      set(USE_GNUTLS ON PARENT_SCOPE)

      set(LIBRARIES ${GNUTLS_LIBRARIES})
      set(INCLUDE_DIR ${GNUTLS_INCLUDE_DIR})
      set(LIBRARY_DIR ${GNUTLS_LIB_DIR})
    endif()

    # Nettle is the primary and required crypto library for GnuTLS
    find_package(Nettle REQUIRED)

    if(NETTLE_FOUND)
      list(APPEND LIBRARIES ${NETTLE_LIBRARIES})
    endif()

  endif()

  set(SSLIMP_LIBRARIES ${LIBRARIES} PARENT_SCOPE)
  set(SSLIMP_LIBRARY_DIR ${LIBRARY_DIR} PARENT_SCOPE)
  set(SSLIMP_INCLUDE_DIR ${INCLUDE_DIR} PARENT_SCOPE)

endfunction()

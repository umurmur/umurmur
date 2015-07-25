include(FindPackageHandleStandardArgs)
include(CheckSymbolExists)

find_path(MBEDTLS_INCLUDE_DIR NAMES "version.h" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "include/mbedtls")
find_path(MBEDTLS_LIB_DIR NAMES "libmbedtls.so" "libmbedtls.dylib" "libmbedtls.a" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "lib" "lib/${CMAKE_LIBRARY_ARCHITECTURE}")

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIB_DIR)
  set(MBEDTLS_LIBRARIES mbedtls)
  set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARIES} mbedcrypto)
  set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARIES} mbedx509)
  check_symbol_exists(MBEDTLS_ZLIB_SUPPORT "${MBEDTLS_INCLUDE_DIR}/version.h" HAVE_ZLIB_SUPPORT)
  if(HAVE_ZLIB_SUPPORT)
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARIES} z)
  endif(HAVE_ZLIB_SUPPORT)
endif(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIB_DIR)

find_package_handle_standard_args(mbedTLS REQUIRED_VARS MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARIES MBEDTLS_LIB_DIR)

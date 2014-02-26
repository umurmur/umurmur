include(FindPackageHandleStandardArgs)
include(CheckSymbolExists)

find_path(POLARSSL_INCLUDE_DIR NAMES "version.h" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "include/polarssl")
find_path(POLARSSL_LIB_DIR NAMES "libpolarssl.so" "libpolarssl.dylib" "libpolarssl.a" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "lib" "lib/${CMAKE_LIBRARY_ARCHITECTURE}")

if(POLARSSL_INCLUDE_DIR AND POLARSSL_LIB_DIR)
  set(POLARSSL_LIBRARIES polarssl)
  check_symbol_exists(POLARSSL_ZLIB_SUPPORT "${POLARSSL_INCLUDE_DIR}/version.h" HAVE_ZLIB_SUPPORT)
  if(HAVE_ZLIB_SUPPORT)
    set(POLARSSL_LIBRARIES ${POLARSSL_LIBRARIES} z)
  endif(HAVE_ZLIB_SUPPORT)
endif(POLARSSL_INCLUDE_DIR AND POLARSSL_LIB_DIR)

find_package_handle_standard_args(PolarSSL REQUIRED_VARS POLARSSL_INCLUDE_DIR POLARSSL_LIBRARIES POLARSSL_LIB_DIR)

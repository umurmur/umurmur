# SPDX-License-Identifier: BSD-3-Clause
#
# Find mbedTLS 3.x or 4.x.
#
# Optional inputs (before find_package):
#   MbedTLS_ROOT  - installation prefix
#   MbedTLS_SLOT  - slotted install name (e.g. mbedtls3 on Arch/FreeBSD)
#
# Imported targets: MbedTLS::mbedtls, MbedTLS::mbedx509, MbedTLS::crypto

include(FindPackageHandleStandardArgs)

set(_MBEDTLS_SEARCH_PREFIXES /opt/homebrew /usr/local /usr/pkg /usr)

# 1) pkg-config (Alpine, Debian, BSDs).
# FIXME: Workaround for Alpine's MbedTLS CMake package that references static libs not in mbedtls-dev.
if(NOT MbedTLS_FOUND)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    if(MbedTLS_SLOT)
      foreach(_libdir IN LISTS _MBEDTLS_SEARCH_PREFIXES)
        if(EXISTS "${_libdir}/lib/${MbedTLS_SLOT}/pkgconfig")
          set(ENV{PKG_CONFIG_PATH}
            "${_libdir}/lib/${MbedTLS_SLOT}/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        endif()
        if(EXISTS "${_libdir}/libdata/${MbedTLS_SLOT}/pkgconfig")
          set(ENV{PKG_CONFIG_PATH}
            "${_libdir}/libdata/${MbedTLS_SLOT}/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        endif()
      endforeach()
    endif()
    pkg_check_modules(_MBEDTLS_mbedtls QUIET mbedtls)
    pkg_check_modules(_MBEDTLS_mbedx509 QUIET mbedx509)
    pkg_check_modules(_MBEDTLS_mbedcrypto QUIET mbedcrypto)
    if(NOT _MBEDTLS_mbedcrypto_FOUND)
      pkg_check_modules(_MBEDTLS_mbedcrypto QUIET tfpsacrypto)
    endif()
    if(_MBEDTLS_mbedtls_FOUND AND _MBEDTLS_mbedx509_FOUND AND _MBEDTLS_mbedcrypto_FOUND)
      set(MbedTLS_INCLUDE_DIR "${_MBEDTLS_mbedtls_INCLUDE_DIRS}")
      find_library(MbedTLS_TLS_LIBRARY NAMES mbedtls
        HINTS ${_MBEDTLS_mbedtls_LIBRARY_DIRS} NO_DEFAULT_PATH)
      find_library(MbedTLS_X509_LIBRARY NAMES mbedx509
        HINTS ${_MBEDTLS_mbedx509_LIBRARY_DIRS} NO_DEFAULT_PATH)
      find_library(MbedTLS_CRYPTO_LIBRARY NAMES mbedcrypto tfpsacrypto
        HINTS ${_MBEDTLS_mbedcrypto_LIBRARY_DIRS} NO_DEFAULT_PATH)
      if(MbedTLS_TLS_LIBRARY AND MbedTLS_X509_LIBRARY AND MbedTLS_CRYPTO_LIBRARY)
        set(MbedTLS_FOUND TRUE)
      endif()
    endif()
  endif()
endif()

# 2) Upstream CMake package (source builds, Homebrew, some distros).
if(NOT MbedTLS_FOUND AND NOT MbedTLS_SLOT)
  find_package(MbedTLS CONFIG QUIET NO_MODULE
    HINTS
      "${MbedTLS_ROOT}"
      "${MbedTLS_ROOT}/lib/cmake/MbedTLS"
      "${MbedTLS_ROOT}/lib64/cmake/MbedTLS"
      ${_MBEDTLS_SEARCH_PREFIXES}
    PATH_SUFFIXES lib/cmake/MbedTLS cmake/MbedTLS
  )
  if(NOT (MbedTLS_FOUND AND TARGET MbedTLS::mbedtls AND TARGET MbedTLS::mbedx509))
    set(MbedTLS_FOUND FALSE)
  endif()
endif()

# 3) Headers and libraries without package metadata.
if(NOT MbedTLS_FOUND)
  set(_MBEDTLS_INCLUDE_SUFFIXES include)
  set(_MBEDTLS_LIBRARY_SUFFIXES lib lib64 libdata)
  if(MbedTLS_SLOT)
    list(APPEND _MBEDTLS_INCLUDE_SUFFIXES "include/${MbedTLS_SLOT}")
    list(APPEND _MBEDTLS_LIBRARY_SUFFIXES
      "lib/${MbedTLS_SLOT}" "lib64/${MbedTLS_SLOT}"
      "libdata/${MbedTLS_SLOT}")
  endif()

  find_path(MbedTLS_INCLUDE_DIR NAMES mbedtls/version.h
    HINTS "${MbedTLS_ROOT}" ${_MBEDTLS_SEARCH_PREFIXES}
    PATH_SUFFIXES ${_MBEDTLS_INCLUDE_SUFFIXES})

  find_library(MbedTLS_TLS_LIBRARY
    NAMES mbedtls mbedtls-3
    HINTS "${MbedTLS_ROOT}" ${_MBEDTLS_SEARCH_PREFIXES}
    PATH_SUFFIXES ${_MBEDTLS_LIBRARY_SUFFIXES})
  find_library(MbedTLS_X509_LIBRARY
    NAMES mbedx509 mbedx509-3
    HINTS "${MbedTLS_ROOT}" ${_MBEDTLS_SEARCH_PREFIXES}
    PATH_SUFFIXES ${_MBEDTLS_LIBRARY_SUFFIXES})
  find_library(MbedTLS_CRYPTO_LIBRARY
    NAMES mbedcrypto mbedcrypto-3 tfpsacrypto tfpsacrypto-1
    HINTS "${MbedTLS_ROOT}" ${_MBEDTLS_SEARCH_PREFIXES}
    PATH_SUFFIXES ${_MBEDTLS_LIBRARY_SUFFIXES})

  if(MbedTLS_INCLUDE_DIR AND MbedTLS_TLS_LIBRARY AND MbedTLS_X509_LIBRARY
      AND MbedTLS_CRYPTO_LIBRARY)
    set(MbedTLS_FOUND TRUE)
  endif()
endif()

# Grab version from headers when not provided by the CMake package.
if(MbedTLS_FOUND AND NOT MbedTLS_VERSION AND MbedTLS_INCLUDE_DIR)
  foreach(_header IN ITEMS build_info.h version.h)
    set(_path "${MbedTLS_INCLUDE_DIR}/mbedtls/${_header}")
    if(NOT EXISTS "${_path}")
      continue()
    endif()
    file(STRINGS "${_path}" _line REGEX "MBEDTLS_VERSION_STRING")
    if(_line MATCHES "\"([0-9]+\\.[0-9]+\\.[0-9]+)\"")
      set(MbedTLS_VERSION "${CMAKE_MATCH_1}")
      break()
    endif()
  endforeach()
endif()

# Imported targets for pkg-config and manual discovery.
if(MbedTLS_FOUND AND NOT TARGET MbedTLS::mbedtls)
  add_library(MbedTLS::crypto UNKNOWN IMPORTED)
  set_target_properties(MbedTLS::crypto PROPERTIES
    IMPORTED_LOCATION "${MbedTLS_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}")

  add_library(MbedTLS::mbedx509 UNKNOWN IMPORTED)
  set_target_properties(MbedTLS::mbedx509 PROPERTIES
    IMPORTED_LOCATION "${MbedTLS_X509_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES MbedTLS::crypto)

  add_library(MbedTLS::mbedtls UNKNOWN IMPORTED)
  set_target_properties(MbedTLS::mbedtls PROPERTIES
    IMPORTED_LOCATION "${MbedTLS_TLS_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES "MbedTLS::mbedx509;MbedTLS::crypto")

  set(MbedTLS_INCLUDE_DIRS "${MbedTLS_INCLUDE_DIR}")
  set(MbedTLS_LIBRARIES MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::crypto)
endif()

# Normalize crypto target names (mbedTLS 4 CONFIG packages export tfpsacrypto).
if(MbedTLS_FOUND)
  set(_MBEDTLS_CRYPTO_REAL "")
  if(TARGET MbedTLS::tfpsacrypto)
    set(_MBEDTLS_CRYPTO_REAL MbedTLS::tfpsacrypto)
  elseif(TARGET MbedTLS::mbedcrypto)
    get_target_property(_type MbedTLS::mbedcrypto TYPE)
    if(NOT _type STREQUAL "ALIAS_LIBRARY")
      set(_MBEDTLS_CRYPTO_REAL MbedTLS::mbedcrypto)
    endif()
  elseif(TARGET MbedTLS::crypto)
    get_target_property(_type MbedTLS::crypto TYPE)
    if(NOT _type STREQUAL "ALIAS_LIBRARY")
      set(_MBEDTLS_CRYPTO_REAL MbedTLS::crypto)
    endif()
  endif()
  if(_MBEDTLS_CRYPTO_REAL)
    if(NOT TARGET MbedTLS::crypto)
      add_library(MbedTLS::crypto ALIAS ${_MBEDTLS_CRYPTO_REAL})
    endif()
    if(NOT TARGET MbedTLS::mbedcrypto)
      add_library(MbedTLS::mbedcrypto ALIAS ${_MBEDTLS_CRYPTO_REAL})
    endif()
  endif()
  if(TARGET MbedTLS::mbedtls AND TARGET MbedTLS::crypto AND NOT MbedTLS_LIBRARIES)
    set(MbedTLS_LIBRARIES MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::crypto)
  endif()
endif()

find_package_handle_standard_args(MbedTLS
  REQUIRED_VARS MbedTLS_FOUND
  VERSION_VAR MbedTLS_VERSION
)

mark_as_advanced(
  MbedTLS_INCLUDE_DIR
  MbedTLS_TLS_LIBRARY
  MbedTLS_X509_LIBRARY
  MbedTLS_CRYPTO_LIBRARY
)

unset(_MBEDTLS_SEARCH_PREFIXES)

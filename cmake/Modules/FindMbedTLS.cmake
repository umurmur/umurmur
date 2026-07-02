# SPDX-License-Identifier: BSD-3-Clause
# (c) Azamat Hackimov <azamat.hackimov@gmail.com>

#[=======================================================================[.rst:
FindMbedTLS
-----------

Find Mbed TLS 4.x library and include files.

IMPORTED Targets
^^^^^^^^^^^^^^^^

``MbedTLS::mbedtls``

``MbedTLS::mbedx509``

``MbedTLS::tfpsacrypto``

``MbedTLS::mbedcrypto`` (alias of ``MbedTLS::tfpsacrypto`` on 4.x)

#]=======================================================================]

include(FindPackageHandleStandardArgs)

find_path(MbedTLS_INCLUDE_DIR mbedtls/version.h
  HINTS /usr/pkg/include /usr/local/include /usr/include
)

mark_as_advanced(MbedTLS_INCLUDE_DIR)

if(MbedTLS_INCLUDE_DIR AND EXISTS "${MbedTLS_INCLUDE_DIR}/mbedtls/build_info.h")
  file(STRINGS "${MbedTLS_INCLUDE_DIR}/mbedtls/build_info.h" MBEDTLS_VERSION_STR
    REGEX "^#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"[\.0-9]+\"")
  string(REGEX REPLACE "^.*MBEDTLS_VERSION_STRING[\t ]+\"([0-9]+\\.[0-9]+\\.[0-9]+)\".*$"
    "\\1" MBEDTLS_VERSION_STR "${MBEDTLS_VERSION_STR}")
  set(MbedTLS_VERSION "${MBEDTLS_VERSION_STR}")
else()
  message(WARNING "No Mbed TLS version information could be parsed from the source headers")
endif()

if(MbedTLS_VERSION AND MbedTLS_VERSION VERSION_LESS "4.0.0")
  message(FATAL_ERROR "Mbed TLS 4.0 or greater is required (found ${MbedTLS_VERSION})")
endif()

get_filename_component(MbedTLS_INCLUDE_PARENT "${MbedTLS_INCLUDE_DIR}" DIRECTORY)

list(APPEND _MBEDTLS_COMPONENTS mbedtls mbedx509 tfpsacrypto)

foreach(v ${_MBEDTLS_COMPONENTS})
  if(v STREQUAL "tfpsacrypto")
    find_library(MbedTLS_${v}_LIBRARY
      NAMES tfpsacrypto tfpsacrypto-1 mbedcrypto-3 mbedcrypto
      PATHS /usr/pkg /usr/local /usr
    )
  else()
    find_library(MbedTLS_${v}_LIBRARY
      NAMES ${v}-3 ${v}
      PATHS /usr/pkg /usr/local /usr
    )
  endif()
  mark_as_advanced(MbedTLS_${v}_LIBRARY)
endforeach()

find_package_handle_standard_args(MbedTLS REQUIRED_VARS
  MbedTLS_mbedtls_LIBRARY
  MbedTLS_mbedx509_LIBRARY
  MbedTLS_tfpsacrypto_LIBRARY
  MbedTLS_INCLUDE_DIR
)

foreach(v ${_MBEDTLS_COMPONENTS})
  if(MbedTLS_${v}_LIBRARY AND NOT TARGET MbedTLS::${v})
    add_library(MbedTLS::${v} UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::${v} PROPERTIES
      IMPORTED_LOCATION "${MbedTLS_${v}_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_PARENT}"
    )
  endif()
endforeach()

if(MbedTLS_FOUND AND TARGET MbedTLS::tfpsacrypto AND NOT TARGET MbedTLS::mbedcrypto)
  add_library(MbedTLS::mbedcrypto ALIAS MbedTLS::tfpsacrypto)
endif()

if(MbedTLS_FOUND)
  set(MbedTLS_INCLUDE_DIRS ${MbedTLS_INCLUDE_PARENT})
  set(MbedTLS_LIBRARIES
    ${MbedTLS_mbedtls_LIBRARY}
    ${MbedTLS_mbedx509_LIBRARY}
    ${MbedTLS_tfpsacrypto_LIBRARY}
  )
endif()

unset(_MBEDTLS_COMPONENTS)

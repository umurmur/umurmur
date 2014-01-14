cmake_minimum_required(VERSION 2.8)

project(umurmurd C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)

find_package(Libconfig REQUIRED)
find_package(ProtobufC REQUIRED)
include(CheckFunctionExists)
include(CheckLibraryExists)

if(SSL MATCHES "openssl")
  find_package(OpenSSL REQUIRED)
  if(OPENSSL_FOUND)
    set(SSLIMP_LIBRARIES ${OPENSSL_LIBRARIES})
    set(SSLIMP_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(SSLIMP_LIBRARY_DIR ${OPENSSL_LIB_DIR})
  endif(OPENSSL_FOUND)
else(SSL MATCHES "openssl")
  find_package(PolarSSL REQUIRED)
  if(POLARSSL_FOUND)
    set(USE_POLARSSL ON)
    set(SSLIMP_LIBRARIES ${POLARSSL_LIBRARIES})
    set(SSLIMP_INCLUDE_DIR ${POLARSSL_INCLUDE_DIR})
    set(SSLIMP_LIBRARY_DIR ${POLARSSL_LIB_DIR})
  endif(POLARSSL_FOUND)
endif(SSL MATCHES "openssl")

check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)

if(NOT HAVE_CLOCK_GETTIME)
  check_library_exists(rt clock_gettime "time.h" HAVE_CLOCK_GETTIME_RT)
  if(NOT HAVE_CLOCK_GETTIME_RT)
    check_library_exists(c clock_get_time "mach/time.h" HAVE_CLOCK_GET_TIME)
    if(NOT HAVE_CLOCK_GET_TIME)
      message(FATAL_ERROR "Didn't find clock_gettime() or clock_get_time!")
    endif()
  else()
    set(LIBRARIES ${LIBRARIES} rt)
  endif()
endif()

set(SOURCE "")
add_subdirectory(src)

configure_file(src/config.h.in ${CMAKE_SOURCE_DIR}/src/config.h)

include_directories(${LIBCONFIG_INCLUDE_DIR} ${PROTOBUFC_INCLUDE_DIR} ${SSLIMP_INCLUDE_DIR}) 
link_directories(${LIBCONFIG_LIB_DIR} ${PROTOBUFC_LIB_DIR} ${SSLIMP_LIB_DIR})

add_executable(umurmurd ${SOURCE})
install(TARGETS umurmurd RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")

add_definitions(${SSLIMP_CFLAGS})
target_link_libraries(umurmurd ${LIBCONFIG_LIBRARIES} ${PROTOBUFC_LIBRARIES} ${SSLIMP_LIBRARIES})

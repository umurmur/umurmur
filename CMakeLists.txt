cmake_minimum_required(VERSION 3.16)

project(umurmurd)

# Custom CMake modules
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

# Versions
set(UMURMUR_CODENAME "Loopy")

set(VERSION_MAJOR "0")
set(VERSION_MINOR "3")
set(VERSION_PATCH "2")

set(RELEASE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(UMURMUR_VERSION ${RELEASE_VERSION})
else()
  find_program(APP_GIT git)
  mark_as_advanced(APP_GIT)
  execute_process(COMMAND ${APP_GIT} rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    RESULT_VARIABLE RETVAL
    OUTPUT_VARIABLE GIT_SHORT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(UMURMUR_VERSION "${RELEASE_VERSION}+git${GIT_SHORT_SHA}")
endif()

project(umurmurd VERSION ${RELEASE_VERSION} LANGUAGES C)

find_package(Libconfig REQUIRED)
find_package(ProtobufC REQUIRED)

include(SelectRTBackend)
SelectRTBackend()

include(SelectTLSBackend)
SelectTLSBackend("${SSL}")

include(Options)
include(Tools)
include(GNUInstallDirs)

include(CheckFunctionExists)
check_function_exists(strlcpy HAVE_STRLCPY)

find_package(Libconfig REQUIRED)
find_package(ProtobufC REQUIRED)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

add_subdirectory(src)

install(
  FILES "umurmur.conf.example"
  DESTINATION "${CMAKE_INSTALL_FULL_SYSCONFDIR}/umurmur"
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
  RENAME "umurmur.conf"
)

message(STATUS "Version: ${UMURMUR_VERSION}")

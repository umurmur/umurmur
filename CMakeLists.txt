cmake_minimum_required(VERSION 3.16)

project(umurmurd VERSION 0.3.2 LANGUAGES C)

# Custom CMake modules
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

# Versions
set(UMURMUR_CODENAME "Loopy")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(UMURMUR_VERSION ${PROJECT_VERSION})

find_package(Git)
if(NOT (CMAKE_BUILD_TYPE STREQUAL "Release") AND Git_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    RESULT_VARIABLE RETVAL
    OUTPUT_VARIABLE GIT_SHORT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(UMURMUR_VERSION "${PROJECT_VERSION}+git${GIT_SHORT_SHA}")
endif()

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

add_subdirectory(src)

install(
  FILES "umurmur.conf.example"
  DESTINATION "${CMAKE_INSTALL_FULL_SYSCONFDIR}/umurmur"
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
  RENAME "umurmur.conf"
)

message(STATUS "Version: ${UMURMUR_VERSION}")

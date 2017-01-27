cmake_minimum_required(VERSION 2.8.3)
project(umurmurd C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)
set(UMURMUR_BINARY_DIR "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${UMURMUR_BINARY_DIR}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "The type of build product that should be produced." FORCE)
endif()

set(CMAKE_C_FLAGS "-std=gnu99 -Wall -Wextra -Werror")
add_definitions("-D_XOPEN_SOURCE -D_GNU_SOURCE")

include(SelectTLSBackend)
include(SelectRTBackend)

SelectRTBackend()
SelectTLSBackend("${SSL}")

include(Options)
include(Tools)

find_package(Libconfig REQUIRED)
find_package(ProtobufC REQUIRED)

add_subdirectory(src)

find_path(OLD_CONFIG_FILE NAMES "umurmur.conf" PATHS ${CMAKE_INSTALL_PREFIX} PATH_SUFFIXES "etc")

if(NOT OLD_CONFIG_FILE)
  install(FILES "umurmur.conf.example" DESTINATION "etc" RENAME "umurmur.conf")
endif()


cmake_minimum_required(VERSION 3.10)
project(umurmurd C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH true)
set(UMURMUR_BINARY_DIR "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${UMURMUR_BINARY_DIR}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "The type of build product that should be produced." FORCE)
endif()

include(SelectTLSBackend)
include(SelectRTBackend)

SelectRTBackend()
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

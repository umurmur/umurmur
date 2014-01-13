project(umurmurd)

cmake_minimum_required(VERSION 2.8)

add_definitions()

include(FindPkgConfig)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckSymbolExists)

pkg_check_modules(LIBCONFIG libconfig)
pkg_check_modules(LIBPROTOBUF libprotobuf-c)

if(DEFINED SSL)
  pkg_check_modules(SSLIMP REQUIRED ${SSL})
else()
  pkg_check_modules(SSLIMP REQUIRED polarssl)
endif()

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
include_directories(include)

add_definitions(${LIBCONFIG_CFLAGS} ${LIBPROTOBUF_CFLAGS} ${SSLIMP_CFLAGS})
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBCONFIG_CFLAGS} ${LIBPROTOBUF_CFLAGS}")

add_executable(umurmurd ${SOURCE})
target_link_libraries(umurmurd ${LIBCONFIG_LIBRARIES} ${LIBPROTOBUF_LIBRARIES} ${SSLIMP_LIBRARIES})

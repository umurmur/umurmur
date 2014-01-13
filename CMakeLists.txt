project(umurmurd)

cmake_minimum_required(VERSION 2.8)

add_definitions()

include(FindPkgConfig)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckSymbolExists)

pkg_check_modules(BASELIBS libconfig)

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

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(SOURCE "")

add_subdirectory(src)
include_directories(include)

add_executable(umurmurd ${SOURCE})
target_link_libraries(umurmurd pthread)

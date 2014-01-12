project(umurmurd)

cmake_minimum_required(VERSION 2.8)

add_definitions()

include(FindPkgConfig)
include(CheckFunctionExists)
include(CheckLibraryExists)

pkg_check_modules(BASELIBS libconfig)
check_function_exists(clock_gettime GAVE_CLOCK_GETTIME)
check_library_exists(rt clock_gettime "time.h" HAVE_CLOCK_GETTIME_RT)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(SOURCE "")

add_subdirectory(src)
include_directories(include)

add_executable(umurmurd ${SOURCE})
target_link_libraries(umurmurd pthread)

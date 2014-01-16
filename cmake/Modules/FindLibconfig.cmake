include(FindPackageHandleStandardArgs)

find_path(LIBCONFIG_INCLUDE_DIR NAMES "libconfig.h" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "include")
find_path(LIBCONFIG_LIB_DIR NAMES "libconfig.so" "libconfig.dylib" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "lib" "lib/${CMAKE_LIBRARY_ARCHITECTURE}")

if(LIBCONFIG_INCLUDE_DIR AND LIBCONFIG_LIB_DIR)
  set(LIBCONFIG_LIBRARIES config)
endif(LIBCONFIG_INCLUDE_DIR AND LIBCONFIG_LIB_DIR)

find_package_handle_standard_args(Libconfig DEFAULT LIBCONFIG_INCLUDE_DIR LIBCONFIG_LIBRARIES LIBCONFIG_LIB_DIR)

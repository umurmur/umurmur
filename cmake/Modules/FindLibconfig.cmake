include(FindPackageHandleStandardArgs)

find_path(LIBCONFIG_INCLUDE_DIR NAMES "libconfig.h")
find_library(LIBCONFIG_LIBRARIES NAMES "config")

find_package_handle_standard_args(Libconfig REQUIRED_VARS LIBCONFIG_INCLUDE_DIR LIBCONFIG_LIBRARIES)

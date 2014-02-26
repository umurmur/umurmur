include(FindPackageHandleStandardArgs)

find_path(PROTOBUFC_INCLUDE_DIR NAMES "protobuf-c.h" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "include/google/protobuf-c")
find_path(PROTOBUFC_LIB_DIR NAMES "libprotobuf-c.so" "libprotobuf-c.dylib" PATHS /usr/pkg /usr/local /usr PATH_SUFFIXES "lib"  "lib/${CMAKE_LIBRARY_ARCHITECTURE}")

if(PROTOBUFC_INCLUDE_DIR AND PROTOBUFC_LIB_DIR)
  set(PROTOBUFC_LIBRARIES protobuf-c)
endif(PROTOBUFC_INCLUDE_DIR AND PROTOBUFC_LIB_DIR)

find_package_handle_standard_args(ProtobufC REQUIRED_VARS PROTOBUFC_INCLUDE_DIR PROTOBUFC_LIBRARIES PROTOBUFC_LIB_DIR)

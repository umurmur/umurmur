include(FindPackageHandleStandardArgs)

find_path(PROTOBUFC_INCLUDE_DIR NAMES "protobuf-c.h" PATH_SUFFIXES "protobuf-c")
find_library(PROTOBUFC_LIBRARIES NAMES "protobuf-c")


find_package_handle_standard_args(ProtobufC REQUIRED_VARS PROTOBUFC_INCLUDE_DIR PROTOBUFC_LIBRARIES)

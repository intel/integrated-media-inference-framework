cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# None

add_subdirectory(c-ares)

# Add C-ARES CMake search path
list(INSERT CMAKE_PREFIX_PATH 0 "${CMAKE_CURRENT_BINARY_DIR}/c-ares/c-ares-prj-prefix/src/c-ares-prj-build/_install_/lib/cmake/c-ares")

# Build the library
set(EXT_PRJ_NAME        "grpc-prj")
set(EXT_PRJ_REPO        "https://github.com/grpc/grpc.git")
set(EXT_PRJ_TAG         "v1.22.0")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Protobuf install path
set(PROTOBUF_CMAKE_DIR  "${CMAKE_CURRENT_BINARY_DIR}/../protobuf/protobuf-prj-prefix/src/protobuf-prj-build/_install_/lib/cmake/protobuf")

# Download, unpack and build the library
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "gRPC build failed!")
endif()

###############################
### Export Imported Library ###
###############################

# Include gRPC cmake files in the search path
list(APPEND CMAKE_PREFIX_PATH ${EXT_PRJ_INSTALL_DIR}/lib/cmake)
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} CACHE INTERNAL "")

# Install the library
install(
  DIRECTORY ${EXT_PRJ_INSTALL_DIR}/lib
  DESTINATION ${CMAKE_INSTALL_PREFIX}
  USE_SOURCE_PERMISSIONS
)

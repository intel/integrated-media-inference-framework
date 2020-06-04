cmake_minimum_required(VERSION 2.8.2)

set(EXT_PRJ_NAME        "protobuf-prj")
set(EXT_PRJ_VERSION     "3.8.0")
set(EXT_PRJ_REPO        "https://github.com/protocolbuffers/protobuf/releases/download/v${EXT_PRJ_VERSION}/protobuf-cpp-${EXT_PRJ_VERSION}.tar.gz")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Download and unpack and build protobuf
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "protobuf build failed!")
endif()

# Include protobuf cmake files in the search path
list(APPEND CMAKE_PREFIX_PATH ${EXT_PRJ_INSTALL_DIR}/lib/cmake)
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} CACHE INTERNAL "")

# Install the protobuf libraries
install(DIRECTORY ${EXT_PRJ_INSTALL_DIR}/lib DESTINATION ${CMAKE_INSTALL_PREFIX} 
        FILES_MATCHING PATTERN "*.so*")

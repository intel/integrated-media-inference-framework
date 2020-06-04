cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# None

# Build the library
set(EXT_PRJ_NAME        "replxx-prj")
set(EXT_PRJ_REPO        "https://github.com/AmokHuginnsson/replxx.git")
set(EXT_PRJ_TAG         "c634cde996610f4d3330e13c0c9e16bf1034382b")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Download, unpack and build the library
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "replxx build failed!")
endif()

# Install the library

###############################
### Export Imported Library ###
###############################

# Export library information
set(PROJECT_NAME libreplxx)
project(${PROJECT_NAME})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
set(LIB_NAME "libreplxx-d.so")
else()
set(LIB_NAME "libreplxx.so")
endif()

add_library(${PROJECT_NAME} IMPORTED SHARED GLOBAL)

set_target_properties(${PROJECT_NAME} PROPERTIES
# IMPORTED_NO_SONAME 1
IMPORTED_SONAME "${LIB_NAME}"
IMPORTED_LOCATION "${EXT_PRJ_INSTALL_DIR}/lib/${LIB_NAME}"
INTERFACE_INCLUDE_DIRECTORIES "${EXT_PRJ_INSTALL_DIR}/include"
)

install(DIRECTORY "${EXT_PRJ_INSTALL_DIR}/lib" DESTINATION "${CMAKE_INSTALL_PREFIX}") 

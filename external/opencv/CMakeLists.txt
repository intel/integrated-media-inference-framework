cmake_minimum_required (VERSION 2.8.12)

set(PROJECT_NAME opencv)
project(${PROJECT_NAME})

# OpenCV Version
set(OPENCV_TAG "4.1.1")

# Build the library
set(EXT_PRJ_NAME        "opencv-prj")
set(EXT_PRJ_REPO        "https://github.com/opencv/opencv.git")
set(EXT_PRJ_TAG         "${OPENCV_TAG}")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/_install_")

# Download, unpack and build the library
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "${PROJECT_NAME} build failed!")
endif()

#################################
### Define the OpenCV target ###
#################################

# Update OpenCV cmake path
set(ENV{OpenCV_DIR} "${CMAKE_CURRENT_BINARY_DIR}/_install_/lib/cmake")

# Install the libraries
install(
  DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/_install_/lib
  DESTINATION ${CMAKE_INSTALL_PREFIX_BASE}/usr 
  USE_SOURCE_PERMISSIONS
)

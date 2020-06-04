cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# Ubuntu: autogen libtool libdrm-dev x11 [libxfixes-dev libxext-dev] (needed for media-driver)
# CentOS: libdrm-devel libXfixes-devel libXext-devel

# Build libva library
set(EXT_PRJ_NAME        "libva-prj")
set(EXT_PRJ_REPO        "https://github.com/intel/libva")
set(EXT_PRJ_TAG       "2.6.0")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Download, unpack and build
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "libva build failed!")
endif()

# Install the library
file(COPY ${EXT_PRJ_INSTALL_DIR}/ DESTINATION ${MEDIASDK_INSTALL_DIR}/usr USE_SOURCE_PERMISSIONS)

###############################
### Export Imported Library ###
###############################

# Export library information
set(PROJECT_NAME libva)
project(${PROJECT_NAME})

add_library(${PROJECT_NAME} IMPORTED SHARED GLOBAL)

set_target_properties(${PROJECT_NAME} PROPERTIES
  # IMPORTED_NO_SONAME 1
  IMPORTED_SONAME "libva.so"
  IMPORTED_LOCATION "${MEDIASDK_INSTALL_DIR}/usr/lib/libva.so"
  INTERFACE_LINK_LIBRARIES "${MEDIASDK_INSTALL_DIR}/usr/lib/libva-drm.so"
  INTERFACE_INCLUDE_DIRECTORIES "${MEDIASDK_INSTALL_DIR}/usr/include"
)

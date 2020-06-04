cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# Ubuntu: libva gmmlib libpciaccess-dev libx11-dev
# CentOS: libva gmmlib libpciaccess-devel libX11-devel

# Build libva library
set(EXT_PRJ_NAME        "media-driver-prj")
set(EXT_PRJ_REPO        "https://github.com/intel/media-driver.git")
set(EXT_PRJ_TAG       "intel-media-19.4.0r")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Dependecies package config
get_target_property(libva_pkg_config libva IMPORTED_LOCATION)
get_filename_component(libva_pkg_config "${libva_pkg_config}" DIRECTORY)

get_target_property(libigdgmm_pkg_config libigdgmm IMPORTED_LOCATION)
get_filename_component(libigdgmm_pkg_config "${libigdgmm_pkg_config}" DIRECTORY)

set(ENV{PKG_CONFIG_PATH} "${libva_pkg_config}/pkgconfig:${libigdgmm_pkg_config}/pkgconfig")

# Download, unpack and build
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "Media Driver build failed!")
endif()

# Install the library
file(COPY ${EXT_PRJ_INSTALL_DIR}/ DESTINATION ${MEDIASDK_INSTALL_DIR}/usr USE_SOURCE_PERMISSIONS)

###############################
### Export Imported Library ###
###############################

# Export library information
set(PROJECT_NAME libigxcmrt)
project(${PROJECT_NAME})

add_library(${PROJECT_NAME} IMPORTED SHARED GLOBAL)

set_target_properties(${PROJECT_NAME} PROPERTIES
  # IMPORTED_NO_SONAME 1
  IMPORTED_SONAME "libigxcmrt.so"
  IMPORTED_LOCATION "${MEDIASDK_INSTALL_DIR}/usr/lib/libigxcmrt.so"
  # INTERFACE_LINK_LIBRARIES "${EXT_PRJ_INSTALL_DIR}/lib/libigxcmrt.so"
  INTERFACE_INCLUDE_DIRECTORIES "${MEDIASDK_INSTALL_DIR}/usr/include"
)

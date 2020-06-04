cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# libva-drm

# Build libva library
set(EXT_PRJ_NAME        "libva-utils-prj")
set(EXT_PRJ_REPO        "https://github.com/intel/libva-utils.git")
set(EXT_PRJ_TAG         "2.4.0")
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Dependecies package config
get_target_property(libva_pkg_config libva IMPORTED_LOCATION)
get_filename_component(libva_pkg_config "${libva_pkg_config}" DIRECTORY)
set(ENV{PKG_CONFIG_PATH} "${libva_pkg_config}/pkgconfig")

# Download, unpack and build
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "libva-utils build failed!")
endif()

# Install the utils
file(COPY ${EXT_PRJ_INSTALL_DIR}/ DESTINATION ${MEDIASDK_INSTALL_DIR}/usr USE_SOURCE_PERMISSIONS)
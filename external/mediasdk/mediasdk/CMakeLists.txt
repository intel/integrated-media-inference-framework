cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# Build the library
set(EXT_PRJ_NAME        "mediasdk-prj")
set(EXT_PRJ_REPO        "https://github.com/Intel-Media-SDK/MediaSDK.git")
set(EXT_PRJ_TAG         ${MEDIASDK_TAG_VERSION})
set(EXT_PRJ_SRC_DIR     "${CMAKE_CURRENT_BINARY_DIR}/${EXT_PRJ_NAME}-prefix/src/${EXT_PRJ_NAME}")
set(EXT_PRJ_BIN_DIR     "${EXT_PRJ_SRC_DIR}-build")
set(EXT_PRJ_INSTALL_DIR "${EXT_PRJ_BIN_DIR}/_install_")

# Download, unpack and build the library
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

execute_process(COMMAND bash -c "export GIT_LFS_SKIP_SMUDGE=1; ${CMAKE_COMMAND} --build ."
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} RESULT_VARIABLE build_retval)

# Make sure the build completed successfully
if(NOT build_retval EQUAL "0")
  message( FATAL_ERROR "MediaSDK build failed!")
endif()

# Install the library
file(COPY ${EXT_PRJ_INSTALL_DIR}/ DESTINATION ${MEDIASDK_INSTALL_DIR}/usr USE_SOURCE_PERMISSIONS)

###############################
### Export Imported Library ###
###############################

# Export library information
set(PROJECT_NAME libmfx)
project(${PROJECT_NAME})

add_library(${PROJECT_NAME} IMPORTED SHARED GLOBAL)

# Include Directories
list(APPEND PROJECT_INCLUDE_DIRS "${MEDIASDK_INSTALL_DIR}/usr/include")
list(APPEND PROJECT_INCLUDE_DIRS "${MEDIASDK_INSTALL_DIR}/usr/include/mfx")

set_target_properties(${PROJECT_NAME} PROPERTIES
  # IMPORTED_NO_SONAME 1
  IMPORTED_SONAME "libmfx.so"
  IMPORTED_LOCATION "${MEDIASDK_INSTALL_DIR}/usr/lib/libmfx.so"
  INTERFACE_LINK_LIBRARIES "${MEDIASDK_INSTALL_DIR}/usr/lib/libmfxhw64.so"
  INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_INCLUDE_DIRS}"
)


add_library(msdk_sample_common IMPORTED SHARED GLOBAL)

set_target_properties(msdk_sample_common PROPERTIES
  IMPORTED_SONAME "libsample_common.so"
  IMPORTED_LOCATION "${MEDIASDK_INSTALL_DIR}/usr/lib/mfx/libsample_common.so"
  INTERFACE_INCLUDE_DIRECTORIES "${MEDIASDK_INSTALL_DIR}/usr/include/sample_common"
)

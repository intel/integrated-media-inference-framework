cmake_minimum_required(VERSION 2.8.2)

###################
### Dependecies ###
###################
# None

set(PROJECT_NAME openvino)
project(${PROJECT_NAME})


#######################################
### Build OpenVINO from source code ###
#######################################

set(EXT_PRJ_NAME        "openvino-prj")

# Build OpenVINO from Github (public repo)
set(EXT_PRJ_REPO        "https://github.com/opencv/dldt.git")
set(EXT_PRJ_TAG         "2019_R3")
set(EXT_PRJ_PATCH       "patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patches/001-centos-build-fix.patch")
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
  message( FATAL_ERROR "openvino build failed!")
endif()

# Copy the artifacts into an intermidiate install directory
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/include/ DESTINATION ${EXT_PRJ_INSTALL_DIR}/external-headers)
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/src/extension DESTINATION ${EXT_PRJ_INSTALL_DIR}/internal-headers/ FILES_MATCHING PATTERN "*.h*")
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/src/inference_engine DESTINATION ${EXT_PRJ_INSTALL_DIR}/internal-headers/ FILES_MATCHING PATTERN "*.h*")
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/bin/intel64/Release/
  DESTINATION ${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/bin
  USE_SOURCE_PERMISSIONS 
  FILES_MATCHING 
  PATTERN "lib" EXCLUDE
  PATTERN "*"
)
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/bin/intel64/Release/lib/
  DESTINATION ${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib
  USE_SOURCE_PERMISSIONS 
  FILES_MATCHING 
    PATTERN "*.so"
    PATTERN "*.mvcmd"
    PATTERN "plugins.xml"
)
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/temp/tbb/lib/libtbb.so.2
  DESTINATION ${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib USE_SOURCE_PERMISSIONS)
file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/thirdparty/clDNN/common/intel_ocl_icd/6.3/linux/Release/bin/x64/libOpenCL.so.1
  DESTINATION ${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib USE_SOURCE_PERMISSIONS)

if(OPENVINO_INTERNAL_REPO)
  file(COPY ${EXT_PRJ_SRC_DIR}/inference-engine/temp/mkltiny_lnx_20190620/lib/libmkl_tiny_tbb.so
    DESTINATION ${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib USE_SOURCE_PERMISSIONS)
endif()


###############################
### Export Imported Library ###
###############################

# Libraries
list(APPEND PROJECT_DEP_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libtbb.so.2")
list(APPEND PROJECT_DEP_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libinference_engine.so")
list(APPEND PROJECT_INST_LIBS "${PROJECT_DEP_LIBS}")
list(APPEND PROJECT_INST_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libclDNNPlugin.so")
list(APPEND PROJECT_INST_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libMKLDNNPlugin.so")
list(APPEND PROJECT_INST_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libclDNN64.so")
list(APPEND PROJECT_INST_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/plugins.xml")
list(APPEND PROJECT_INST_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libOpenCL.so.1")

# Additional libraries for internall OpenVINO build
if(OPENVINO_INTERNAL_REPO)
  list(APPEND PROJECT_INST_LIBS "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libmkl_tiny_tbb.so")
endif()

# Define the target
add_library(${PROJECT_NAME} IMPORTED SHARED GLOBAL)
set_target_properties(${PROJECT_NAME} PROPERTIES
  # IMPORTED_NO_SONAME 1
  IMPORTED_SONAME "libinference_engine.so"
  IMPORTED_LOCATION "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/libinference_engine.so"
  INTERFACE_LINK_LIBRARIES "${PROJECT_LIBS}"
  INTERFACE_INCLUDE_DIRECTORIES "${EXT_PRJ_INSTALL_DIR}/external-headers"
  INTERNAL_INCLUDE_DIRECTORIES "${EXT_PRJ_INSTALL_DIR}/internal-headers"
  INTERNAL_LIB_DIRECTORIES "${EXT_PRJ_INSTALL_DIR}/usr/share/openvino/lib/"
)

# Install the library locally
install(DIRECTORY ${EXT_PRJ_INSTALL_DIR}/usr DESTINATION ${CMAKE_INSTALL_PREFIX_BASE} USE_SOURCE_PERMISSIONS)

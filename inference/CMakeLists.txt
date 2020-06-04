cmake_minimum_required(VERSION 2.8)

# Project Name
set(CMAKE_CXX_STANDARD 11)
set(PROJECT_NAME imif_inference)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

find_package(OpenCV REQUIRED)

# Project Source Files
file(GLOB_RECURSE sources
  src/*.cpp
)

# Build an executable using the provided sources
add_executable(${PROJECT_NAME} ${sources})

# OpenVINO Include Directories
get_target_property(OPENVINO_INC_INT openvino INTERNAL_INCLUDE_DIRECTORIES)
target_include_directories(${PROJECT_NAME}
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/plugins/include
      ${CMAKE_CURRENT_SOURCE_DIR}/src/irp
      ${CMAKE_CURRENT_SOURCE_DIR}/src/ilb
      # OpenCV
      ${OpenCV_INCLUDE_DIRS}
      # Private OpenVINO Includes
      ${OPENVINO_INC_INT}
)

# MESSAGE(STATUS "Include dirs ${OpenCV_INCLUDE_DIRS}")
# MESSAGE(STATUS "LINK LIBRARIES ${OpenCV_LIBS}")

get_target_property(openvino_ie_libs openvino INTERNAL_LIB_DIRECTORIES)

# Linked libraries
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    dl pthread
    imif_common
    imif_yaml
    ${openvino_ie_libs}/libcpu_extension.so
    ${openvino_ie_libs}/libHeteroPlugin.so
    openvino
    ${OpenCV_LIBS}
)

# Build dependecies
add_dependencies(${PROJECT_NAME} 
  imif_common 
  imif_yaml
  openvino
)

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(plugins)

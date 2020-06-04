cmake_minimum_required(VERSION 2.8)
#set(CMAKE_VERBOSE_MAKEFILE ON)

# Project Name
set(PROJECT_NAME irp_plugin_resnet50)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

find_package(OpenCV REQUIRED)

FILE(GLOB PluginSources *.cpp)
add_library(${PROJECT_NAME} SHARED ${PluginSources})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${IMIF_VERSION} SOVERSION ${IMIF_VERSION_MAJOR})

target_include_directories(${PROJECT_NAME}
  PRIVATE 
  ../include
    ${OpenCV_INCLUDE_DIRS}
)
add_dependencies(${PROJECT_NAME}  imif_common)
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
  imif_common
  ${OpenCV_LIBS}
)

install( TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

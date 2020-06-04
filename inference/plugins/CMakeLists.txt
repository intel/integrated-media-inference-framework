cmake_minimum_required(VERSION 2.8)
#set(CMAKE_VERBOSE_MAKEFILE ON)

# Project Name
set(PROJECT_NAME imif_irp_plugins)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

add_subdirectory(default)
add_subdirectory(detection_output)
add_subdirectory(resnet50)
add_subdirectory(ssd_resnet34)
add_subdirectory(yolov3)

cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_mgmt)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

## For Debug ##
# set(CMAKE_VERBOSE_MAKEFILE ON)
##

# Project Source Files
file(GLOB sources
  src/*.cpp
)

# Build an executable using the provided sources
add_executable(${PROJECT_NAME} ${sources})

# Linked libraries
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    imif_common
    imif_yaml
)

# Build dependecies
add_dependencies(${PROJECT_NAME}
  imif_common
  imif_yaml
)

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

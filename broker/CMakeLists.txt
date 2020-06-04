cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_broker)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

## For Debug ##
# set(CMAKE_VERBOSE_MAKEFILE ON)
##

# Project Source files
file(GLOB source_files
  src/*.cpp
)

# Build an executable using the provided sources
add_executable(${PROJECT_NAME} ${source_files})

# Linked libraries
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    imif_common
)

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

# Unit tests
add_subdirectory(tests)

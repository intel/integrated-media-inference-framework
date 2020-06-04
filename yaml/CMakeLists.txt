cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_yaml)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

## For Debug ##
# set(CMAKE_VERBOSE_MAKEFILE ON)
##

# Project Source Files
file(GLOB sources
  *.cpp
)

# Build an executable using the provided sources
add_library(${PROJECT_NAME} SHARED ${sources})

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Linked libraries
target_link_libraries(${PROJECT_NAME}
  PRIVATE
  yaml
  imif_common
)

# Make the library importable from the install directory
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_tcp_sender)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

find_package(OpenCV REQUIRED)

## For Debug ##
# set(CMAKE_VERBOSE_MAKEFILE ON)
##

# Project Source Files
file(GLOB sources
  src/*.cpp
)

# Build an executable using the provided sources
add_executable(${PROJECT_NAME} ${sources})

# Search include directories
target_include_directories(${PROJECT_NAME}
  PRIVATE

    # OpenCV
    ${OpenCV_INCLUDE_DIRS}

)

# Linked libraries
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    imif_common
    imif_custom
    ${OpenCV_LIBS}
)

# Build dependecies
add_dependencies(${PROJECT_NAME}
  imif_common
  imif_custom
)

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

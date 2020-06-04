cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_mdecode)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

# Project Version
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 1)
set(PROJECT_VERSION_PATCH 0)
set(PROJECT_VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})

add_definitions(-DMFX_VA -DLIBVA_SUPPORT -DLIBVA_DRM_SUPPORT)

## For Debug ##
# set(CMAKE_VERBOSE_MAKEFILE ON)
##

# Ignore some (CentOS specific) build warnings
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-implicit-fallthrough -Wno-unknown-pragmas -Wno-unused-but-set-variable -Wno-unused-variable -Wno-unused-value -Wno-unused-function")

# Project Source Files
file(GLOB sources
  src/*.cpp
)

# Build an executable using the provided sources
add_executable(${PROJECT_NAME} ${sources})

# Search include directories
target_include_directories(${PROJECT_NAME}
  PRIVATE
    # System folders
    /usr/include/libdrm
)

# Linked libraries
target_link_libraries(${PROJECT_NAME} 
  PRIVATE
    dl pthread drm libva libmfx
    imif_common
    msdk_sample_common
)

# Build dependecies
add_dependencies(${PROJECT_NAME} 
  imif_common 
  libmfx
)

# Install
install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

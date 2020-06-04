cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_mgmt_lib)
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

# Sources Files
file(GLOB_RECURSE src ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

# Build the library
add_library(${PROJECT_NAME} SHARED ${src})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${IMIF_VERSION} SOVERSION ${IMIF_VERSION_MAJOR})

# Includes
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Linked libraries
target_link_libraries(${PROJECT_NAME} 
  PUBLIC
    imif_common
    imif_yaml
)

# Build dependecies
add_dependencies(${PROJECT_NAME}
  imif_common
  imif_yaml
)

# Make the library importable from the install directory
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install include files
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include/mgmt/)

cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_custom)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

# Find required protobuf package
find_package(protobuf REQUIRED)

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

# Include the root main dir (protobuf classes) and generate the classes
set(CMAKE_INCLUDE_CURRENT_DIR TRUE)

# Protobuf files
file(GLOB_RECURSE proto_files
    ${CMAKE_CURRENT_SOURCE_DIR}/*.proto
)

# Build the library
add_library(${PROJECT_NAME} SHARED 
    ${proto_files}
)

# Generate CPP Files
protobuf_generate(TARGET ${PROJECT_NAME} LANGUAGE cpp IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR})

# Generate Python Files
protobuf_generate(TARGET ${PROJECT_NAME} LANGUAGE python IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${IMIF_VERSION} SOVERSION ${IMIF_VERSION_MAJOR})

# Includes
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>          # For generated protobuf classes
        # $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>  # For generated protobuf classes
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(${PROJECT_NAME} 
    PUBLIC
        protobuf::libprotobuf
)

# Make the library importable from the install directory
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

MACRO(SUBDIRLIST result curdir)
  file(GLOB children RELATIVE "${curdir}" "${curdir}/*")
  set(dirlist "")
  foreach(child ${children})
    if((IS_DIRECTORY "${curdir}/${child}") AND (NOT "${child}" STREQUAL "messages") AND (NOT "${child}" STREQUAL "autogen"))
      list(APPEND dirlist "${child}")
    endif()
  endforeach()
  set(${result} ${dirlist})
endmacro()

SUBDIRLIST(SUBDIRS ${CMAKE_CURRENT_SOURCE_DIR})

foreach(subdir ${SUBDIRS})
  add_subdirectory("${subdir}")
endforeach()


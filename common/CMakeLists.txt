cmake_minimum_required(VERSION 2.8)

# Project Name
set(PROJECT_NAME imif_common)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

# Find required protobuf package
find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)
include(cmake/grpc_generate.cmake)

# Set the base path for the current module
set(MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

# Include the root main dir (protobuf classes) and generate the classes
set(CMAKE_INCLUDE_CURRENT_DIR TRUE)

# Set debug flag
if (CMAKE_BUILD_TYPE STREQUAL Debug) 
    add_compile_definitions(COMMON_DEBUG_FLAG)
endif()

# Common Sources
file(GLOB_RECURSE common_src ${MODULE_PATH}/src/*.cpp)

# Protobuf files
file(GLOB_RECURSE proto_files
    ${CMAKE_CURRENT_SOURCE_DIR}/include/messages/*.proto
)

# gRPC files
file(GLOB grpc_files
    ${CMAKE_CURRENT_SOURCE_DIR}/include/messages/grpc/*.proto
)

# Generate C++ gRPC Files
grpc_generate(CPP CPP_GRPC_SRCS CPP_GRPC_HDRS ${CMAKE_CURRENT_BINARY_DIR} ${grpc_files})

# Generate Python gRPC Files
grpc_generate(PYTHON PYTHON_GRPC_SRCS PYTHON_GRPC_HDRS ${CMAKE_CURRENT_BINARY_DIR} ${grpc_files})

# Build the library
add_library(${PROJECT_NAME} SHARED 
    ${common_src} 
    ${proto_files}
    ${CPP_GRPC_SRCS}
    ${PYTHON_GRPC_SRCS}
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
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>  # For generated protobuf classes
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(${PROJECT_NAME} 
    PUBLIC
        easylogging
        protobuf::libprotobuf
        gRPC::grpc++
        stdc++fs
)

# Make the library importable from the install directory
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

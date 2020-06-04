cmake_minimum_required (VERSION 2.8.12)

# Base directory for the built artifacts
set(ELPP_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/_install_")

# Download and unpack and build protobuf
configure_file(CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# Project Name
set(PROJECT_NAME easylogging)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

# Shared library sources
file(GLOB_RECURSE sources ${ELPP_INSTALL_DIR}/include/*.cc)

# Shared library
add_library(${PROJECT_NAME} SHARED ${sources})

# Includes
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${ELPP_INSTALL_DIR}/include>
        $<INSTALL_INTERFACE:${ELPP_INSTALL_DIR}/include>
)

# ELPP Definitions - Added as public since all modules that use
# the easylogging++ library should define these
target_compile_definitions(${PROJECT_NAME} 
    PUBLIC 
        ELPP_FORCE_USE_STD_THREAD
        ELPP_NO_DEFAULT_LOG_FILE
        ELPP_FEATURE_CRASH_LOG
        ELPP_STL_LOGGING
        ELPP_LOG_UNORDERED_MAP
        ELPP_LOG_UNORDERED_SET
        ELPP_THREAD_SAFE
)

# Make the library importable from the install directory
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

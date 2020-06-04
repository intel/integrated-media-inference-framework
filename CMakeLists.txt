cmake_minimum_required(VERSION 2.8.12)

set(PROJECT_NAME IMIF-OSS)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT}${ColourReset}")

include(FindPkgConfig)

# Load variables from a given file
macro(loadVars VARSFILE)
  if(EXISTS "${VARSFILE}")
    file(STRINGS "${VARSFILE}" ConfigContents)
    foreach(NameAndValue ${ConfigContents})
      string(REGEX REPLACE "^[ ]+" "" NameAndValue ${NameAndValue}) # Strip leading spaces
      string(REGEX MATCH "^[^=]+" Name ${NameAndValue}) # Find variable name
      string(REPLACE "${Name}=" "" Value ${NameAndValue}) # Find the value
      string(REPLACE "\"" "" Value ${Value}) # Remove quotes
      message(STATUS "Loading variable '${Name}'") # Set the variable
      set(${Name} "${Value}")
    endforeach()
  else()
    message(FATAL_ERROR "loadVars: can't load file ${VARSFILE}")
  endif()
endmacro()

# Load environment variables
loadVars($ENV{IMIF_ENV_FILE})

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.8.0")
      message(FATAL_ERROR "gcc version (${CMAKE_CXX_COMPILER_VERSION} not supported, minumum is 4.8.0")
    endif()
endif()

include(GNUInstallDirs)

# Search local cmake folder first
list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_SOURCE_DIR}/cmake)

# Update output directories for easy deployment
# set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Override the install prefix
set(CMAKE_INSTALL_PREFIX_BASE ${CMAKE_BINARY_DIR}/_install_)
set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX_BASE}/opt/intel/imif)

# Override default LIBDIR (on CentOS the default is lib64)
set(CMAKE_INSTALL_LIBDIR "lib")

# Relative libraries search path
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib:$ORIGIN/../lib64:$ORIGIN/")

# Default Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pthread -Wno-unused-parameter -Wno-missing-field-initializers -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS} -std=c++17 -fpermissive")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -Wformat -Wformat-security -Wl,-S -fPIE -fPIC")
if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 4.9)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fstack-protector-strong")
else()
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fstack-protector")
endif()
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${CMAKE_C_FLAGS_RELEASE}")

# Get GIT revision
execute_process(COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/build.sh" "gitrev" 
    OUTPUT_STRIP_TRAILING_WHITESPACE 
    OUTPUT_VARIABLE IMIF_GIT_REV)

if (NOT DEFINED IMIF_VERSION)
  # Project Version
  set(IMIF_VERSION_MAJOR 1)
  set(IMIF_VERSION_MINOR 0)
  set(IMIF_VERSION_PATCH 0)
  set(IMIF_VERSION ${IMIF_VERSION_MAJOR}.${IMIF_VERSION_MINOR}.${IMIF_VERSION_PATCH})

  execute_process(COMMAND "date" "+%F %T" OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE PROJECT_BUILD_DATE)
  add_definitions(-DIMIF_VERSION="${IMIF_VERSION}")
  add_definitions(-DIMIF_BUILD_DATE="${PROJECT_BUILD_DATE}")
  add_definitions(-DIMIF_REVISION="xxx")
endif()

message(STATUS "Version: ${IMIF_VERSION}")
message(STATUS "Build Date: ${PROJECT_BUILD_DATE}")

# Enable unit tests
enable_testing()

# Modules
add_subdirectory(external)
add_subdirectory(common)
add_subdirectory(rtsp_client)
add_subdirectory(custom)
add_subdirectory(broker)
add_subdirectory(mstream)
add_subdirectory(mdecode)
add_subdirectory(inference)
add_subdirectory(mgmt)
add_subdirectory(lib)
add_subdirectory(cli)
add_subdirectory(yaml)

# Install global files
file(GLOB configs
    ${CMAKE_CURRENT_SOURCE_DIR}/config/*.yaml
)
install(FILES ${configs} DESTINATION ${CMAKE_INSTALL_PREFIX}/config) 


if( NOT DEFINED ENV{IMIF_EXTERNAL_IMIF_SH} )
  file(GLOB config_service
      ${CMAKE_CURRENT_SOURCE_DIR}/config/*.conf
  )
  install(FILES ${config_service} DESTINATION ${CMAKE_INSTALL_PREFIX}/config)
  install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/imif.sh DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
endif()

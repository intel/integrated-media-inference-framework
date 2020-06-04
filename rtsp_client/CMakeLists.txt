# IMIF support RTSP client. In case non available, it will build a dummy
# wrapper of a rtsp client.
# To add a real RTSP client:
# 1. set EXTERNAL_RTSP_CLIENT 
# 2. provide a librtsp_client.so that complies with the API's in imif_rtsp_client.h
if (DEFINED EXTERNAL_RTSP_CLIENT)
  return()
endif()

# Project Name
set(PROJECT_NAME rtsp_client)
project(${PROJECT_NAME})
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${ColourReset}")

FILE(GLOB sources *.cpp)
add_library(${PROJECT_NAME} SHARED ${sources})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${IMIF_VERSION} SOVERSION ${IMIF_VERSION_MAJOR})

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(${PROJECT_NAME} 
  PRIVATE
  imif_common
)

# Make the library importable from the install directory
install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

set(MEDIASDK_TAG_VERSION        "intel-mediasdk-19.4.0")

set(MEDIASDK_INSTALL_DIR    "${CMAKE_CURRENT_BINARY_DIR}/_install_")

# MediaSDK Dependecies
add_subdirectory(libva)
add_subdirectory(libva-utils)
add_subdirectory(gmmlib)
add_subdirectory(media-driver)
add_subdirectory(mediasdk)

# Install the MediaSDK
install(DIRECTORY ${MEDIASDK_INSTALL_DIR}/
        DESTINATION ${CMAKE_INSTALL_PREFIX_BASE} 
        USE_SOURCE_PERMISSIONS
        FILES_MATCHING 
          PATTERN "include" EXCLUDE
          PATTERN "*")
    
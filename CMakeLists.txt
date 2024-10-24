cmake_minimum_required(VERSION 3.22)

project(ProofSystem LANGUAGES C CXX)

add_subdirectory(src)

include(cmake/functions.cmake)

# Install Headers
install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" FILES_MATCHING PATTERN "*.h*")


# Install Targets
set(GeniusKDF_CONFIG_DESTINATION_DIR "lib/cmake/ProofSystem")
install(EXPORT ProofSystemTargets
    FILE ProofSystemTargets.cmake
    DESTINATION ${ProofSystem_CONFIG_DESTINATION_DIR}
)


include(CMakePackageConfigHelpers)

# generate the config file that is includes the exports
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfig.cmake"
    INSTALL_DESTINATION "lib/cmake/examples"
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

# generate the version file for the config file
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfigVersion.cmake"
    VERSION "${VERSION_STRING}.${SUBVERSION_STRING}"
    COMPATIBILITY AnyNewerVersion
)
# install the configuration file
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfig.cmake
    DESTINATION ${ProofSystem_CONFIG_DESTINATION_DIR}
)


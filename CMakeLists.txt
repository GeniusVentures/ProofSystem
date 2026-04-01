cmake_minimum_required(VERSION 3.22)

project(ProofSystem
    VERSION 1.0.0
    DESCRIPTION "evmrelay and rlp/rlpx/discv4/discv5/eth library for C++"
    LANGUAGES C CXX
)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost REQUIRED COMPONENTS random)
include_directories(${Boost_INCLUDE_DIRS})

if(BUILD_TESTING)
    find_package(GTest CONFIG REQUIRED)
endif()

add_subdirectory(src)

# Install Targets
set(ProofSystem_CONFIG_DESTINATION_DIR "lib/cmake/ProofSystem")

install(EXPORT ProofSystem
    NAMESPACE ProofSystem::
    FILE ProofSystemTargets.cmake
    DESTINATION ${ProofSystem_CONFIG_DESTINATION_DIR}
)

include(CMakePackageConfigHelpers)

# generate the config file that is includes the exports
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfig.cmake"
    INSTALL_DESTINATION ${ProofSystem_CONFIG_DESTINATION_DIR}
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
    ${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfigVersion.cmake
    DESTINATION ${ProofSystem_CONFIG_DESTINATION_DIR}
)

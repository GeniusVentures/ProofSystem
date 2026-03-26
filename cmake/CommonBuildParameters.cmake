# BOOST VERSION TO USE
set(BOOST_MAJOR_VERSION "1" CACHE STRING "Boost Major Version")
set(BOOST_MINOR_VERSION "85" CACHE STRING "Boost Minor Version")
set(BOOST_PATCH_VERSION "0" CACHE STRING "Boost Patch Version")

# convenience settings
set(BOOST_VERSION "${BOOST_MAJOR_VERSION}.${BOOST_MINOR_VERSION}.${BOOST_PATCH_VERSION}")
set(BOOST_VERSION_2U "${BOOST_MAJOR_VERSION}_${BOOST_MINOR_VERSION}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(DEFINED USE_BOOST_INCLUDE_POSTFIX)
        set(BOOST_INCLUDE_POSTFIX "/boost-${BOOST_VERSION_2U}" CACHE STRING "Boost include postfix")
endif()

# --------------------------------------------------------
# Set config of GTest
set(GTest_DIR "${_THIRDPARTY_BUILD_DIR}/GTest/lib/cmake/GTest")
set(GTest_INCLUDE_DIR "${_THIRDPARTY_BUILD_DIR}/GTest/include")
find_package(GTest CONFIG REQUIRED)
include_directories(${GTest_INCLUDE_DIR})
add_compile_definitions(CRYPTO3_CODEC_BASE58)

# Boost should be loaded before libp2p v0.1.2
# --------------------------------------------------------
# Set config of Boost project
set(_BOOST_ROOT "${_THIRDPARTY_BUILD_DIR}/boost/build")
set(Boost_LIB_DIR "${_BOOST_ROOT}/lib")
set(Boost_INCLUDE_DIR "${_BOOST_ROOT}/include${BOOST_INCLUDE_POSTFIX}")
set(Boost_DIR "${Boost_LIB_DIR}/cmake/Boost-${BOOST_VERSION}")
set(boost_headers_DIR "${Boost_LIB_DIR}/cmake/boost_headers-${BOOST_VERSION}")
set(boost_random_DIR "${Boost_LIB_DIR}/cmake/boost_random-${BOOST_VERSION}")
set(boost_system_DIR "${Boost_LIB_DIR}/cmake/boost_system-${BOOST_VERSION}")
set(boost_filesystem_DIR "${Boost_LIB_DIR}/cmake/boost_filesystem-${BOOST_VERSION}")
set(boost_program_options_DIR "${Boost_LIB_DIR}/cmake/boost_program_options-${BOOST_VERSION}")
set(boost_date_time_DIR "${Boost_LIB_DIR}/cmake/boost_date_time-${BOOST_VERSION}")
set(boost_regex_DIR "${Boost_LIB_DIR}/cmake/boost_regex-${BOOST_VERSION}")
set(boost_atomic_DIR "${Boost_LIB_DIR}/cmake/boost_atomic-${BOOST_VERSION}")
set(boost_chrono_DIR "${Boost_LIB_DIR}/cmake/boost_chrono-${BOOST_VERSION}")
set(boost_log_DIR "${Boost_LIB_DIR}/cmake/boost_log-${BOOST_VERSION}")
set(boost_log_setup_DIR "${Boost_LIB_DIR}/cmake/boost_log_setup-${BOOST_VERSION}")
set(boost_thread_DIR "${Boost_LIB_DIR}/cmake/boost_thread-${BOOST_VERSION}")
set(boost_unit_test_framework_DIR "${Boost_LIB_DIR}/cmake/boost_unit_test_framework-${BOOST_VERSION}")
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_NO_SYSTEM_PATHS ON)
option(Boost_USE_STATIC_RUNTIME "Use static runtimes" ON)

# header only libraries must not be added here
find_package(Boost REQUIRED COMPONENTS date_time filesystem random regex system thread log log_setup program_options)
include_directories(${Boost_INCLUDE_DIRS})

# --------------------------------------------------------
# set config for this project
option(BUILD_TESTING "Build tests" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_APPS "Enable application targets." FALSE)
option(BUILD_EXAMPLES "Enable demonstration targets." FALSE)
option(BUILD_DOCS "Enable documentation targets." FALSE)
set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_LIST_DIR}/docs" CACHE STRING "Specify doxygen output directory")

include_directories(
        "${CMAKE_CURRENT_LIST_DIR}/../include"
)
# --------------------------------------------------------
# Set config of crypto3
add_library(crypto3::algebra INTERFACE IMPORTED)
add_library(crypto3::block INTERFACE IMPORTED)
add_library(crypto3::blueprint INTERFACE IMPORTED)
add_library(crypto3::codec INTERFACE IMPORTED)
add_library(crypto3::math INTERFACE IMPORTED)
add_library(crypto3::multiprecision INTERFACE IMPORTED)
add_library(crypto3::pkpad INTERFACE IMPORTED)
add_library(crypto3::pubkey INTERFACE IMPORTED)
add_library(crypto3::random INTERFACE IMPORTED)
add_library(crypto3::zk INTERFACE IMPORTED)
add_library(marshalling::core INTERFACE IMPORTED)
add_library(marshalling::crypto3_algebra INTERFACE IMPORTED)
add_library(marshalling::crypto3_multiprecision INTERFACE IMPORTED)
add_library(marshalling::crypto3_zk INTERFACE IMPORTED)

set_target_properties(crypto3::algebra PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::block PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::blueprint PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::codec PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::math PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::multiprecision PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::pkpad PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::pubkey PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::random PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(crypto3::zk PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(marshalling::core PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(marshalling::crypto3_algebra PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(marshalling::crypto3_multiprecision PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)
set_target_properties(marshalling::crypto3_zk PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ZKLLVM_BUILD_DIR}/zkLLVM/include"
)

# zkLLVM
set(zkLLVM_INCLUDE_DIR "${ZKLLVM_BUILD_DIR}/zkLLVM/include")
include_directories(${zkLLVM_INCLUDE_DIR})

# circifier
set(LLVM_DIR "${ZKLLVM_BUILD_DIR}/zkLLVM/lib/cmake/llvm")
find_package(LLVM CONFIG REQUIRED)

add_subdirectory(${PROJECT_ROOT}/SGProofCircuits ${CMAKE_BINARY_DIR}/SGProofCircuits)
include_directories(
        ${PROJECT_ROOT}/SGProofCircuits
)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../src/ ${CMAKE_BINARY_DIR}/src)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../test ${CMAKE_BINARY_DIR}/test)
endif()

# Install Headers
install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" FILES_MATCHING PATTERN "*.h*")

install(TARGETS ${PROJECT_NAME} EXPORT ProofSystemTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FRAMEWORK DESTINATION ${CMAKE_INSTALL_PREFIX}
        BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
        EXPORT ProofSystemTargets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ProofSystem
        NAMESPACE ProofSystem::
)

include(CMakePackageConfigHelpers)

# generate the config file that is includes the exports
configure_package_config_file(${PROJECT_ROOT}/cmake/config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ProofSystem
        NO_SET_AND_CHECK_MACRO
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

# generate the version file for the config file
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfigVersion.cmake"
        VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}"
        COMPATIBILITY AnyNewerVersion
)

# install the configuration file
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/ProofSystemConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ProofSystem
)

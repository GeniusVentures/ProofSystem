add_library(KeyGeneration STATIC BitcoinKeyGenerator.cpp ElGamalKeyGenerator.cpp EthereumKeyGenerator.cpp)
target_include_directories(KeyGeneration PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/ProofSystem>
    )
target_link_libraries(
    KeyGeneration
    PUBLIC
    Boost::boost
)
target_compile_definitions(
    KeyGeneration PUBLIC CRYPTO3_CODEC_BASE58
)

sgnus_install(KeyGeneration)

add_library(KeyGeneration STATIC BitcoinKeyGenerator.cpp ElGamalKeyGenerator.cpp EthereumKeyGenerator.cpp)
target_include_directories(
    KeyGeneration PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
target_compile_definitions(
    KeyGeneration PUBLIC CRYPTO3_CODEC_BASE58
)
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
if (MSVC)
    target_compile_options(KeyGeneration PRIVATE /constexpr:steps10000000)
endif()
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_compile_options(KeyGeneration PRIVATE -fconstexpr-steps=1000000000 -fconstexpr-depth=1000000000)
endif()

sgnus_install(KeyGeneration)

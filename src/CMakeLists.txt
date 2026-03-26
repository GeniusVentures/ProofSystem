add_library(ProofSystem STATIC BitcoinKeyGenerator.cpp ElGamalKeyGenerator.cpp EthereumKeyGenerator.cpp PrimeNumbers.cpp)

if (MSVC)
    target_compile_options(ProofSystem PRIVATE /constexpr:steps1500000)
endif()

target_include_directories(ProofSystem PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(
    ProofSystem
    PUBLIC
    Boost::boost
    Boost::random
)

target_compile_definitions(
        ProofSystem PUBLIC CRYPTO3_CODEC_BASE58
)
if (MSVC)
    target_compile_options(ProofSystem PRIVATE /constexpr:steps10000000)
endif()
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_compile_options(ProofSystem PRIVATE -fconstexpr-steps=1000000000 -fconstexpr-depth=1000000000)
endif()

sgnus_install(ProofSystem)

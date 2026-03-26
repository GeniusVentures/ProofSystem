add_library(ProofSystem STATIC BitcoinKeyGenerator.cpp ElGamalKeyGenerator.cpp EthereumKeyGenerator.cpp PrimeNumbers.cpp)

if (MSVC)
    target_compile_options(ProofSystem PRIVATE /constexpr:steps1500000)
endif()

print("*** Current cmake current list dir: ${CMAKE_CURRENT_LIST_DIR}")
# Specify public include directory
target_include_directories(ProofSystem PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include/>
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${crypto3_INCLUDE_DIR}>
)

target_link_libraries( ProofSystem
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

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../include/ProofSystem/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ProofSystem
        FILES_MATCHING PATTERN "*.hpp"
)

# Install the core library and attach it to the export set consumed by
# the top-level install(EXPORT ProofSystem ...) call.
install(TARGETS ProofSystem
        EXPORT ProofSystem
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES      DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ProofSystem
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ProofSystem
        FRAMEWORK     DESTINATION ${CMAKE_INSTALL_PREFIX}
        BUNDLE        DESTINATION ${CMAKE_INSTALL_BINDIR}

)

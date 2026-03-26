# ProofSystem Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.15)

if (BUILD_TESTING)
    addtest(main_test
            main_test.cpp
            BitcoinKeyGenerator_test.cpp
            ECElGamalKeyGenerator_test.cpp
            ElGamalKeyGenerator_test.cpp
            EthereumKeyGenerator_test.cpp
            KDFGenerator_test.cpp
            MPCVerifierCircuit_test.cpp
            TransactionVerifierCircuit_test.cpp
            Requestor.cpp
    )

    target_link_libraries(main_test
            ProofSystem
            SGProofCircuits
    )

endif()
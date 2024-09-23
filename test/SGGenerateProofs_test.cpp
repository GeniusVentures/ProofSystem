/**
 * @file     GenerateProofs_test.cpp
 * @brief    Test the generation of proofs with proof carrying data using a proof
 */

#include <gtest/gtest.h>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include "SGProofGenerator.hpp"

using namespace nil::crypto3::algebra::curves;

TEST(SGProofGeneratorTest, GenerateAndVerifyProofs) {
    // Initialize the elliptic curve parameters
    pallas::init_public_params();

    // Define a generator point (example)
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);

    // Generate keypair for the proofs
    auto keypair = r1cs_gg_ppzksnark_generator<pallas>();

    // Define public flags
    std::vector<typename pallas::base_field_type::value_type> public_flags = {1, 2, 3};

    // Generate Genesis Proof with Flags
    proof_type genesis_proof = SGProofGenerator::generate_genesis_proof_with_flags(keypair, generator, public_flags);

    // Extract and verify public flags from Genesis Proof
    SGProofGenerator::extract_and_verify_public_flags(genesis_proof, public_flags);

    // Generate Account Creation Proof with Flags
    proof_type account_creation_proof = SGProofGenerator::generate_account_creation_proof_with_flags(genesis_proof, keypair, generator, public_flags);

    // Extract and verify public flags from Account Creation Proof
    SGProofGenerator::extract_and_verify_public_flags(account_creation_proof, public_flags);

    // Generate Transfer Proof with Flags
    proof_type transfer_proof = SGProofGenerator::generate_transfer_proof_with_flags(account_creation_proof, keypair, generator, public_flags);

    // Extract and verify public flags from Transfer Proof
    SGProofGenerator::extract_and_verify_public_flags(transfer_proof, public_flags);

    // Output the results to ensure the process works
    std::cout << "Genesis Proof: " << genesis_proof << std::endl;
    std::cout << "Account Creation Proof: " << account_creation_proof << std::endl;
    std::cout << "Transfer Proof: " << transfer_proof << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
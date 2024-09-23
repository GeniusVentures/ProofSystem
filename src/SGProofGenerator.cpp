/**
 * @file     GenerateProofs.cpp
 * @brief    Implement the SGProofGenerator class with functions for generating proofs
 */

#include "SGProofGenerator.hpp"

proof_type SGProofGenerator::generate_genesis_proof_with_flags(
    keypair_type& keypair,
    typename pallas::template g1_type<coordinates::affine>::value_type generator,
    const std::vector<typename pallas::base_field_type::value_type>& public_flags) {

    // Define the circuit for Genesis block proof with public flags
    protoboard<typename pallas::base_field_type::value_type> pb;

    // Use generator and setup constraints here...

    // Integrate public flags into the primary input
    primary_input_type primary_input = pb.primary_input();
    primary_input.insert(primary_input.end(), public_flags.begin(), public_flags.end());

    // Generate auxiliary input
    auxiliary_input_type auxiliary_input = pb.auxiliary_input();

    return r1cs_gg_ppzksnark_prover<pallas>(keypair.pk, primary_input, auxiliary_input);
}

proof_type SGProofGenerator::generate_account_creation_proof_with_flags(
    proof_type& genesis_proof,
    keypair_type& keypair,
    typename pallas::template g1_type<coordinates::affine>::value_type generator,
    const std::vector<typename pallas::base_field_type::value_type>& public_flags) {

    // Define the circuit for Account Creation proof with public flags
    protoboard<typename pallas::base_field_type::value_type> pb;

    // Use generator and setup constraints here...

    // Integrate the genesis proof and public flags as input
    primary_input_type primary_input = pb.primary_input();
    primary_input.insert(primary_input.end(), genesis_proof.begin(), genesis_proof.end());
    primary_input.insert(primary_input.end(), public_flags.begin(), public_flags.end());

    // Generate auxiliary input
    auxiliary_input_type auxiliary_input = pb.auxiliary_input();

    return r1cs_gg_ppzksnark_prover<pallas>(keypair.pk, primary_input, auxiliary_input);
}

proof_type SGProofGenerator::generate_transfer_proof_with_flags(
    proof_type& prev_proof,
    keypair_type& keypair,
    typename pallas::template g1_type<coordinates::affine>::value_type generator,
    const std::vector<typename pallas::base_field_type::value_type>& public_flags) {

    // Define the circuit for Transfer proof with public flags
    protoboard<typename pallas::base_field_type::value_type> pb;

    // Use generator and setup constraints here...

    // Integrate the previous proof and public flags as input
    primary_input_type primary_input = pb.primary_input();
    primary_input.insert(primary_input.end(), prev_proof.begin(), prev_proof.end());
    primary_input.insert(primary_input.end(), public_flags.begin(), public_flags.end());

    // Generate auxiliary input
    auxiliary_input_type auxiliary_input = pb.auxiliary_input();

    return r1cs_gg_ppzksnark_prover<pallas>(keypair.pk, primary_input, auxiliary_input);
}

std::vector<typename pallas::base_field_type::value_type> SGProofGenerator::extract_public_flags(
    proof_type& proof) {

    // Create a vector to hold the extracted public flags
    size_t flag_count = /* Define how many flags you expect to extract */;
    std::vector<typename pallas::base_field_type::value_type> public_flags(flag_count);

    // Extract public flags from the proof primary input
    for (size_t i = 0; i < flag_count; ++i) {
        public_flags[i] = proof.primary_input[proof.primary_input.size() - flag_count + i];
    }

    return public_flags;
}
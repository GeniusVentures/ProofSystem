/**
 * @file     SGProofGenerator.hpp
 * @brief    Define the SGProofGenerator class with functions for generating proofs
 */

#ifndef SGPROOFGENERATOR_HPP
#define SGPROOFGENERATOR_HPP

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/zk/snark.hpp>
#include <nil/crypto3/zk/snark/ppzksnark/r1cs_gg_ppzksnark.hpp>

using namespace nil::crypto3::algebra::curves;
using namespace nil::crypto3::zk::snark;

typedef r1cs_gg_ppzksnark_proof<pallas> proof_type;
typedef r1cs_gg_ppzksnark_keypair<pallas> keypair_type;
typedef r1cs_gg_ppzksnark_primary_input<pallas> primary_input_type;
typedef r1cs_gg_ppzksnark_auxiliary_input<pallas> auxiliary_input_type;

class SGProofGenerator {
public:
    static proof_type generate_genesis_proof_with_flags(
        keypair_type& keypair,
        typename pallas::template g1_type<coordinates::affine>::value_type generator,
        const std::vector<typename pallas::base_field_type::value_type>& public_flags);

    static proof_type generate_account_creation_proof_with_flags(
        proof_type& genesis_proof,
        keypair_type& keypair,
        typename pallas::template g1_type<coordinates::affine>::value_type generator,
        const std::vector<typename pallas::base_field_type::value_type>& public_flags);

    static proof_type generate_transfer_proof_with_flags(
        proof_type& prev_proof,
        keypair_type& keypair,
        typename pallas::template g1_type<coordinates::affine>::value_type generator,
        const std::vector<typename pallas::base_field_type::value_type>& public_flags);

    static proof_type generate_mpc_verifier_circuit_proof(
        proof_type& previous_proof,
        keypair_type& keypair,
        typename pallas::template g1_type<coordinates::affine>::value_type generator,
        const std::vector<typename pallas::base_field_type::value_type>& public_flags);

    static std::vector<typename pallas::base_field_type::value_type> extract_public_flags(
        proof_type& proof);
};

#endif // SGPROOFGENERATOR_HPP
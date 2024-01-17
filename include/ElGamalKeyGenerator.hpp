/**
 * @file       ElGamalKeyGenerator.hpp
 * @brief      El Gamal key generetor header file
 * @date       2024-01-17
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _EL_GAMAL_KEY_GENERATOR_HPP_
#define _EL_GAMAL_KEY_GENERATOR_HPP_
#include <memory>

#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/blueprint/blueprint/r1cs/circuit.hpp>
#include <nil/crypto3/
#include "ElGamalTypes.hpp"

using namespace nil::crypto3;
class ElGamalKeyGenerator
{
public:
    ElGamalKeyGenerator( /* args */ );
    ~ElGamalKeyGenerator();

private:
    std::shared_ptr<elgamal_keypair_type> key_pair;
    std::shared_ptr<proof_keypair_type>   prover_key_pair;
    components::blueprint                 elgamal_bp;
    /* data */
};

ElGamalKeyGenerator::ElGamalKeyGenerator( /* args */ )
{

    components::block_variable<field_type>            m_block( elgamal_bp, m.size() );
    components::block_variable<test_policy::field_type>            eid_block( elgamal_bp, eid.size() );
    components::digest_variable<test_policy::field_type>           sn_digest( elgamal_bp, test_policy::hash_component::digest_bits );
    components::digest_variable<test_policy::field_type>           root_digest( elgamal_bp, test_policy::merkle_hash_component::digest_bits );
    components::blueprint_variable_vector<test_policy::field_type> address_bits_va;
    address_bits_va.allocate( bp, test_policy::tree_depth );
    test_policy::merkle_proof_component                 path_var( bp, test_policy::tree_depth );
    components::block_variable<test_policy::field_type> sk_block( bp, secret_keys[proof_idx].size() );
    test_policy::voting_component                       vote_var( bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
                                                                  components::blueprint_variable<test_policy::field_type>( 0 ) );

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    std::make_shared<elgamal_keypair_type>(
        generate_keypair<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>( rnd, { gg_keypair, m.size() } ); )
}

ElGamalKeyGenerator::~ElGamalKeyGenerator()
{
}

#endif

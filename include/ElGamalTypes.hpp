/**
 * @file       ElGamalTypes.hpp
 * @brief      Header file of El Gamal types
 * @date       2024-01-17
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _ELGAMAL_TYPES_HPP_
#define _ELGAMAL_TYPES_HPP_

#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>
#include <nil/crypto3/marshalling/pubkey/types/elgamal_verifiable.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/pedersen.hpp>
//#include <nil/blueprint/components/voting/r1cs/encrypted_input_voting.hpp>
#include <nil/crypto3/hash/find_group_hash.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include <nil/crypto3/random/rfc6979.hpp>

using namespace nil::crypto3;
namespace elgamal
{
    using CurveType               = algebra::curves::bls12_381;                         ///< ECDSA uses secp256k curve
    using base_field_type         = typename CurveType::base_field_type;                ///< The base field type is dependant on the curve
    using scalar_field_type       = typename CurveType::scalar_field_type;              ///< The scalar field type is dependant on the curve
    using scalar_field_value_type = typename scalar_field_type::value_type;             ///< The value type fo the scalar field type
    using random_generator_type   = random::algebraic_random_device<scalar_field_type>; ///< A random algebraic generator
    using hash_type               = hashes::sha2<256>;
    using encryption_scheme       = pubkey::elgamal_verifiable<CurveType>; ///< The deterministic generator used by Ethereum key pair
    using proof_system            = typename encryption_scheme::proof_system_type;
    using elgamal_keypair_type    = encryption_scheme::keypair_type;
    using proof_keypair_type      = proof_system::keypair_type;
    using cypher_type             = encryption_scheme::cipher_type;

    using hash_curve_type                 = algebra::curves::jubjub;
    using base_points_generator_hash_type = hashes::sha2<256>;
    using hash_params                     = hashes::find_group_hash_default_params;
    using hash_component                  = hashes::pedersen<hash_params, base_points_generator_hash_type>;
    using merkle_hash_component           = hash_component;
    using merkle_hash_type                = merkle_hash_component;
    using field_type                      = typename hash_component::group_type::field_type;
    //using voting_component                = components::encrypted_input_voting<2, hash_component, merkle_hash_component, field_type>;
    //using merkle_proof_component          = typename voting_component::merkle_proof_component;
    //using generator_type          = random::rfc6979<scalar_field_value_type, merkle_hash_type>;        ///< RFC6979 deterministic generator
    //using padding_policy          = pubkey::padding::emsa1<scalar_field_value_type, merkle_hash_type>; ///< Ethereum passing policy
    //using policy_type             = pubkey::ecdsa<CurveType, padding_policy, generator_type>;              ///< Ethereum policy type
    //using signature_type          = typename pubkey::public_key<policy_type>::signature_type;
}

#endif //_ECDSA_TYPES_HPP_
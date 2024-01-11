/**
 * @file       EthereumKeyPairParams.hpp
 * @brief      Ethereum types header file
 * @date       2023-12-06
 * @author     Super Genius (ken@gnus.ai)
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef ETHEREUM_KEY_PAIR_PARAMS_HPP
#define ETHEREUM_KEY_PAIR_PARAMS_HPP

#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include "ECDSATypes.hpp"
using namespace nil::crypto3;

namespace ethereum
{
    using CurveType               = ecdsa_t::CurveType;                        ///< Curve type used by Ethereum keys
    using base_field_type         = typename ecdsa_t::base_field_type;         ///< Ethereum base field type
    using scalar_field_type       = typename ecdsa_t::scalar_field_type;       ///< Ethereum scalar field type
    using scalar_field_value_type = typename ecdsa_t::scalar_field_value_type; ///< Ethereum value from the scalar field type
    using random_generator_type   = ecdsa_t::random_generator_type;            ///< Random generator type, to generate new Ethereum keys/addresses

    using hash_type      = hashes::keccak_1600<256>;                                   ///< The hash type used by Ethereum address derivation
    using generator_type = ecdsa_t::generator_type<hash_type>;                         ///< The deterministic generator used by Ethereum key pair
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>; ///< Ethereum passing policy
    using policy_type    = pubkey::ecdsa<CurveType, padding_policy, generator_type>;   ///< Ethereum policy type
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;   ///< Ethereum signature type

} // namespace ethereum

#endif

// ETHEREUM_KEY_PAIR_PARAMS_HPP

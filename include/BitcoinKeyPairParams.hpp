/**
 * @file       BitcoinKeyPairParams.hpp
 * @brief      Bitcoin types header file
 * @date       2023-12-06
 * @author     Super Genius (ken@gnus.ai)
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef BITCOIN_KEY_PAIR_PARAMS_HPP
#define BITCOIN_KEY_PAIR_PARAMS_HPP

#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include "ECDSATypes.hpp"

using namespace nil::crypto3;

namespace bitcoin
{

    using CurveType               = ecdsa_t::CurveType;                        ///< Curve type used by Bitcoin keys
    using base_field_type         = typename ecdsa_t::base_field_type;         ///< Bitcoin base field type
    using scalar_field_type       = typename ecdsa_t::scalar_field_type;       ///< Bitcoin scalar field type
    using scalar_field_value_type = typename ecdsa_t::scalar_field_value_type; ///< Bitcoin value from the scalar field type
    using random_generator_type   = ecdsa_t::random_generator_type;            ///< Random generator type, to generate new Bitcoin keys/addresses

    using hash_type      = hashes::sha2<256>;                                          ///< The hash type used by Bitcoin address derivation
    using generator_type = ecdsa_t::generator_type<hash_type>;                         ///< The deterministic generator used by Bitcoin key pair
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>; ///< Bitcoin passing policy
    using policy_type    = pubkey::ecdsa<CurveType, padding_policy, generator_type>;   ///< Bitcoin policy type
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;   ///< Bitcoin signature type

} // namespace bitcoin

#endif

// BITCOIN_KEY_PAIR_PARAMS_HPP

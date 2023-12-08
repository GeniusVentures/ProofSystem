//
// Created by Super Genius on 12/6/23.
//

#ifndef ETHEREUM_KEY_PAIR_PARAMS_HPP
#define ETHEREUM_KEY_PAIR_PARAMS_HPP

#include "nil/crypto3/pubkey/ecdsa.hpp"
#include "nil/crypto3/hash/keccak.hpp"
#include "nil/crypto3/pkpad/emsa/emsa1.hpp"
#include "nil/crypto3/algebra/curves/secp_k1.hpp"
#include "nil/crypto3/random/algebraic_random_device.hpp"

using namespace nil::crypto3;

namespace ethereum {

    using CurveType = algebra::curves::secp256k1;

    using scalar_field_type = typename CurveType::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;

    using hash_type = hashes::keccak_1600<256>;

    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;

    using generator_type = random::algebraic_random_device<scalar_field_type>;

    using policy_type = pubkey::ecdsa<CurveType, padding_policy, generator_type>;

    using signature_type = typename pubkey::public_key<policy_type>::signature_type;

} // namespace ethereum


#endif

// ETHEREUM_KEY_PAIR_PARAMS_HPP


//
// Created by Super Genius on 12/6/23.
//

#ifndef BITCOIN_KEY_PAIR_PARAMS_HPP
#define BITCOIN_KEY_PAIR_PARAMS_HPP

#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include "ECDSATypes.hpp"

using namespace nil::crypto3;

namespace bitcoin
{

    using CurveType               = ecdsa_t::CurveType;
    using base_field_type         = typename ecdsa_t::base_field_type;
    using scalar_field_type       = typename ecdsa_t::scalar_field_type;
    using scalar_field_value_type = typename ecdsa_t::scalar_field_value_type;
    using generator_type          = ecdsa_t::generator_type;

    using hash_type      = hashes::sha2<256>;
    using padding_policy = pubkey::padding::emsa1<scalar_field_value_type, hash_type>;
    using policy_type    = pubkey::ecdsa<CurveType, padding_policy, generator_type>;
    using signature_type = typename pubkey::public_key<policy_type>::signature_type;

} // namespace bitcoin

#endif

// BITCOIN_KEY_PAIR_PARAMS_HPP

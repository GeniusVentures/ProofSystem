/**
 * @file       ECDSATypes.hpp
 * @brief      Common types and definitions of ECDSA 
 * @date       2024-01-04
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _ECDSA_TYPES_HPP_
#define _ECDSA_TYPES_HPP_

#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/rfc6979.hpp>

using namespace nil::crypto3;
namespace ecdsa_t
{
    using CurveType               = algebra::curves::secp256k1;                         ///< ECDSA uses secp256k curve
    using base_field_type         = typename CurveType::base_field_type;                ///< The base field type is dependant on the curve
    using scalar_field_type       = typename CurveType::scalar_field_type;              ///< The scalar field type is dependant on the curve
    using scalar_field_value_type = typename scalar_field_type::value_type;             ///< The value type fo the scalar field type
    using random_generator_type   = random::algebraic_random_device<scalar_field_type>; ///< A random algebraic generator
    template <typename hash_type>
    using generator_type = random::rfc6979<scalar_field_value_type, hash_type>; ///< RFC6979 deterministic generator
}

#endif //_ECDSA_TYPES_HPP_

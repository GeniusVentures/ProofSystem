/**
 * @file       ECDSATypes.hpp
 * @brief      Common types and definitions of ECDSA 
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _ECDSA_TYPES_HPP_
#define _ECDSA_TYPES_HPP_

namespace ecdsa
{
    using CurveType               = algebra::curves::secp256k1;
    using base_field_type         = typename CurveType::base_field_type;
    using scalar_field_type       = typename CurveType::scalar_field_type;
    using scalar_field_value_type = typename scalar_field_type::value_type;
    using generator_type          = random::algebraic_random_device<scalar_field_type>;
}

#endif //_ECDSA_TYPES_HPP_

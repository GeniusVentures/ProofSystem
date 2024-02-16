/**
 * @file       ECELGamalTypes.hpp
 * @brief      
 * @date       2024-02-16
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _EC_ELGAMAL_TYPES_HPP
#define _EC_ELGAMAL_TYPES_HPP

#include <utility>

#include <nil/crypto3/random/rfc6979.hpp>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/algebra/marshalling.hpp>
#include "util.hpp"
#include "PrimeNumbers.hpp"

using namespace nil::crypto3::algebra;
template <typename CurveType>
struct ECElGamalPoint
{
    typedef typename CurveType::template g1_type<>::value_type curve_point_type;
    typedef typename CurveType::base_field_type::integral_type coeff_type;

    static constexpr coeff_type a_coeff      = CurveType::template g1_type<>::params_type::a;
    static constexpr coeff_type b_coeff      = CurveType::template g1_type<>::params_type::b;
    static constexpr coeff_type prime_number = CurveType::base_field_type::modulus;

    explicit ECElGamalPoint( const cpp_int &m_value )
    {
        cpp_int possible_x = 256 * m_value;
        cpp_int possible_y = -1;
        for ( auto i = 0; i < 256; ++i )
        {
            auto y_squared = CalcPossibleYSquared( possible_x + i );
            possible_y     = PrimeNumbers::SqrtMod( y_squared, prime_number );
            if ( possible_y > 0 )
            {
                possible_x = possible_x + i;
                break;
            }
        }
        if ( possible_y < 0 )
        {
            throw std::runtime_error( "No possible Y found in 256 attempts" );
        }

        typename CurveType::base_field_type::value_type z_data_one = 1;
        typename CurveType::base_field_type::value_type x_base     = static_cast<typename CurveType::base_field_type::value_type>( possible_x );
        typename CurveType::base_field_type::value_type y_base     = static_cast<typename CurveType::base_field_type::value_type>( possible_y );
        //std::cout << "x base " << std::hex << x_base << std::endl;
        //std::cout << "y base " << std::hex << y_base << std::endl;
        curve_point = std::make_shared<curve_point_type>( x_base, y_base, z_data_one );

        //std::cout << "is well formed " << curve_point->is_well_formed() << std::endl;
    }

    explicit ECElGamalPoint( const curve_point_type &m_value )
    {
        curve_point = std::make_shared<curve_point_type>( m_value );
    }
    std::shared_ptr<curve_point_type> curve_point;

    ECElGamalPoint operator+( const ECElGamalPoint &other )
    {
        curve_point_type point_this  = *this->curve_point;
        curve_point_type point_other = *other.curve_point;
        curve_point_type new_point   = point_this + point_other;
        //std::cout << "point_this " << point_this.to_affine().X.data << std::endl;
        //std::cout << "point_other " << point_other.to_affine().X.data << std::endl;
        //std::cout << "new_point " << new_point.to_affine().X.data << std::endl;
        return ECElGamalPoint( new_point );
    }
    ECElGamalPoint operator-( const ECElGamalPoint &other ) const
    {
        curve_point_type point_this  = *this->curve_point;
        curve_point_type point_other = *other.curve_point;
        curve_point_type new_point   = point_this - point_other;
        return ECElGamalPoint( new_point );
    }

    cpp_int UnMap( void )
    {
        cpp_int retval;

        retval = static_cast<cpp_int>( curve_point->to_affine().X.data );
        retval /= 256;
        return retval;
    }

private:
    cpp_int CalcPossibleYSquared( const cpp_int &x_value )
    {
        auto x_cube = PrimeNumbers::PowHighPrec( x_value, 3 );
        return ( x_cube + static_cast<cpp_int>( b_coeff ) );
    }
};

template <typename CurveType, typename Padding, typename GeneratorType, typename DistributionType = void>
struct PublicKey
{
    typedef CurveType curve_type;
    typedef Padding   padding_policy;

    typedef nil::crypto3::pubkey::padding::encoding_accumulator_set<padding_policy> internal_accumulator_type;

    typedef typename curve_type::scalar_field_type              scalar_field_type;
    typedef typename scalar_field_type::value_type              scalar_field_value_type;
    typedef typename curve_type::template g1_type<>             g1_type;
    typedef typename g1_type::value_type                        g1_value_type;
    typedef typename curve_type::base_field_type::integral_type base_integral_type;
    typedef typename scalar_field_type::modular_type            scalar_modular_type;

    typedef g1_value_type                                               public_key_type;
    typedef std::pair<scalar_field_value_type, scalar_field_value_type> signature_type;

    PublicKey( const public_key_type &key ) : pubkey( key )
    {
        //std::cout << "pub key " << std::hex << pubkey.to_affine().X.data << std::endl;
    }
    PublicKey( const std::string &key_string )
    {
        auto z_data_one = g1_value_type::field_type::value_type::one();

        std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( key_string.data(), key_string.size() );

        auto y_data = nil::marshalling::bincode::field<typename curve_type::base_field_type>::template field_element_from_bytes<
            std::vector<std::uint8_t>::iterator>( key_vector.begin(), key_vector.begin() + key_vector.size() / 2 );
        auto x_data = nil::marshalling::bincode::field<typename curve_type::base_field_type>::template field_element_from_bytes<
            std::vector<std::uint8_t>::iterator>( key_vector.begin() + key_vector.size() / 2, key_vector.end() );

        pubkey = public_key_type( x_data.second, y_data.second, z_data_one );
        //std::cout << "pub key imported " << std::hex << pubkey.to_affine().X.data << std::endl;
    }

    inline public_key_type pubkey_data() const
    {
        return pubkey;
    }

protected:
    public_key_type pubkey;
};

template <typename CurveType, typename Padding, typename GeneratorType, typename DistributionType = void>
struct PrivateKey : public PublicKey<CurveType, Padding, GeneratorType, DistributionType>
{
    typedef PublicKey<CurveType, Padding, GeneratorType, DistributionType> base_type;

    typedef CurveType                   curve_type;
    typedef Padding                     padding_policy;
    typedef GeneratorType               generator_type;
    typedef DistributionType            distribution_type;
    typedef typename Padding::hash_type hash_type;

    typedef nil::crypto3::pubkey::padding::encoding_accumulator_set<padding_policy> internal_accumulator_type;

    typedef typename base_type::scalar_field_value_type scalar_field_value_type;
    typedef typename base_type::g1_value_type           g1_value_type;
    typedef typename base_type::base_integral_type      base_integral_type;
    typedef typename base_type::scalar_modular_type     scalar_modular_type;

    typedef scalar_field_value_type             private_key_type;
    typedef typename base_type::public_key_type public_key_type;
    typedef typename base_type::signature_type  signature_type;

    PrivateKey( const private_key_type &key ) : privkey( key ), base_type( generate_public_key( key ) )
    {
        // std::cout << "prv key " << std::hex << privkey << std::endl;
    }

    static inline public_key_type generate_public_key( const private_key_type &key )
    {
        return key * public_key_type::one();
    }

    const private_key_type GetPrivateKeyScalar() const
    {
        return privkey;
    }

protected:
    private_key_type privkey;
};

#endif

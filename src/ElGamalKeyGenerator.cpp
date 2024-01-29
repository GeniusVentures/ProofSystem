/**
 * @file       ElGamalKeyGenerator.cpp
 * @brief      Source file of El Gamal Key Generator module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#include "ElGamalKeyGenerator.hpp"
#include "PrimeNumbers.hpp"
#include <boost/math/common_factor_rt.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::multiprecision;

ElGamalKeyGenerator::ElGamalKeyGenerator()
{
    cpp_int value = 0;
    bool    ret   = PrimeNumbers::GenerateSafePrime<256>( 10, value );

    if ( ret == false )
    {
        throw std::runtime_error( "Prime number not found" );
    }

    cpp_int order = ( value - 1 ) / 2;

    cpp_int generator = 0;

    for ( ;; )
    {
        generator = PrimeNumbers::GetRandomNumber( 2, value - 1 ); // get a random number 1 < g < p-1
        if ( boost::math::gcd( generator, order ) == 1 )           // must be an elment of Zp*
        {
            if ( powm( generator, order, value ) == 1 ) // check if g^q mod p = 1 (if the element is a generator of subgroup G)
                break;
        }
    }

    std::pair<cpp_int, cpp_int> generator_pair = std::make_pair( value, generator );

    cpp_int private_key_scalar = 0;
    for ( ;; )
    {
        private_key_scalar = PrimeNumbers::GetRandomNumber( 2, value - 1 );
        cpp_int gcd        = boost::math::gcd( private_key_scalar, value );
        if ( gcd == 1 )
            break;
    }

    std::pair<cpp_int, std::pair<cpp_int, cpp_int>> sk = std::make_pair( private_key_scalar, generator_pair );

    // public key A
    cpp_int                                         public_key_value = powm( generator, private_key_scalar, value );
    std::pair<cpp_int, std::pair<cpp_int, cpp_int>> pk               = std::make_pair( public_key_value, generator_pair );

    /**std::cout << "Safeprime p = " << value << std::endl;
    std::cout << "order as (p-1/2) = " << order << std::endl;
    std::cout << "Generator g = " << generator << std::endl;
    std::cout << "Private key a = " << private_key_scalar << std::endl;
    std::cout << "Public key A = " << public_key_value << std::endl;**/
}

ElGamalKeyGenerator::~ElGamalKeyGenerator()
{
}
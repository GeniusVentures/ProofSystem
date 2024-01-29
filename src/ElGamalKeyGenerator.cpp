/**
 * @file       ElGamalKeyGenerator.cpp
 * @brief      Source file of El Gamal Key Generator module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#include "ElGamalKeyGenerator.hpp"
#include "PrimeNumbers.hpp"
#include <boost/math/common_factor_rt.hpp>

ElGamalKeyGenerator::ElGamalKeyGenerator()
{
    //PrivateKey key(CreateGeneratorParams());
    private_key = std::make_shared<PrivateKey>(CreateGeneratorParams());
    public_key = std::make_shared<PublicKey>(*private_key);
}

ElGamalKeyGenerator::GeneratorParamsType ElGamalKeyGenerator::CreateGeneratorParams(void)
{
    cpp_int             prime_number = 0;

    bool ret = PrimeNumbers::GenerateSafePrime<256>( 10, prime_number );

    if ( ret == false )
    {
        throw std::runtime_error( "Prime number not found" );
    }

    cpp_int order = ( prime_number - 1 ) / 2;

    cpp_int generator = 0;

    for ( ;; )
    {
        generator = PrimeNumbers::GetRandomNumber( 2, prime_number - 1 ); // get a random number 1 < g < p-1
        if ( boost::math::gcd( generator, order ) == 1 )                  // must be an elment of Zp*
        {
            if ( powm( generator, order, prime_number ) == 1 ) // check if g^q mod p = 1 (if the element is a generator of subgroup G)
                break;
        }
    }

    return std::make_pair( prime_number, generator );
}

ElGamalKeyGenerator::~ElGamalKeyGenerator()
{
}
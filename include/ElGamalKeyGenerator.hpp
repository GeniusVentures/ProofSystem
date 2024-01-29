/**
 * @file       ElGamalKeyGenerator.hpp
 * @brief      El Gamal key generetor header file
 * @date       2024-01-17
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _EL_GAMAL_KEY_GENERATOR_HPP_
#define _EL_GAMAL_KEY_GENERATOR_HPP_
#include <memory>

#include "ElGamalTypes.hpp"
#include "PrimeNumbers.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::multiprecision;
class ElGamalKeyGenerator
{
private:
    using GeneratorParamsType = std::pair<cpp_int, cpp_int>;
    struct Params
    {
    protected:
        GeneratorParamsType p_g;
    };

    GeneratorParamsType CreateGeneratorParams( void );

public:
    struct PublicKey : public Params
    {

    protected:
        cpp_int public_key_scalar;
    };
    struct PrivateKey : public PublicKey
    {
        PrivateKey( GeneratorParamsType p_g )
        {
            auto prime = std::get<0>( p_g );
            for ( ;; )
            {
                private_key_scalar = PrimeNumbers::GetRandomNumber( 2, prime - 1 );
                cpp_int gcd        = boost::math::gcd( private_key_scalar, prime );
                if ( gcd == 1 )
                    break;
            }
            public_key_scalar = GeneratePublicKey( p_g );
        }

    private:
        cpp_int GeneratePublicKey( GeneratorParamsType &p_g )
        {
            return powm( std::get<1>( p_g ), private_key_scalar, std::get<0>( p_g ) );
        }
        cpp_int private_key_scalar;
    };
    ElGamalKeyGenerator( /* args */ );
    ~ElGamalKeyGenerator();

private:
    std::shared_ptr<PrivateKey> private_key;
    std::shared_ptr<PublicKey>  public_key;
};

#endif

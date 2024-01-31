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
    using CypherTextType      = std::pair<cpp_int, cpp_int>;

    /**
     * @brief      Prime and generator parameter struct
     */
    struct Params
    {
        /**
         * @brief       Returns the prime number and its generator
         * @return      @ref GeneratorParamsType 
         */
        const GeneratorParamsType GetParams( void ) const
        {
            return p_g;
        }

    protected:
        GeneratorParamsType p_g; ///< Pair of prime number and its generator
    };

    /**
     * @brief       Create prime number and generator
     * @return      A new set of prime number and generator @ref GeneratorParamsType 
     */
    GeneratorParamsType CreateGeneratorParams( void );

public:
    struct PublicKey : public Params
    {
        cpp_int public_key_scalar;
    };
    struct PrivateKey : public PublicKey
    {
        PrivateKey( GeneratorParamsType &&new_p_g ) //: PublicKey(new_p_g)
        {
            private_key_scalar = PrimeNumbers::GetRandomNumber( new_p_g.first );
            public_key_scalar  = GeneratePublicKey( new_p_g );
            PublicKey::p_g     = new_p_g;
        }

        cpp_int private_key_scalar;

    private:
        cpp_int GeneratePublicKey( GeneratorParamsType &p_g )
        {
            return powm( p_g.second, private_key_scalar, p_g.first );
        }
    };
    static CypherTextType EncryptData( PublicKey &pubkey, std::vector<uint8_t> &data_vector );
    static CypherTextType EncryptData( PublicKey &pubkey, cpp_int &data );
    template <typename T>
    static T DecryptData( PrivateKey &prvkey, CypherTextType &encrypted_data );
    ElGamalKeyGenerator( /* args */ );
    ~ElGamalKeyGenerator();
    PublicKey &GetPublicKey( void ) const
    {
        return *public_key;
    }
    PrivateKey &GetPrivateKey( void ) const
    {
        return *private_key;
    }

private:
    std::shared_ptr<PrivateKey> private_key; ///< Private key instance
    std::shared_ptr<PublicKey>  public_key;  ///< Public key instance
};

#endif

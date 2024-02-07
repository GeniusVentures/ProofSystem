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
    using GeneratorParamsType = std::pair<cpp_int, cpp_int>;
    using CypherTextType      = std::pair<cpp_int, cpp_int>;

private:
    /**
     * @brief      Prime and generator parameter struct
     */
    struct Params
    {
        /**
         * @brief       Construct a new Params object
         * @param[in]   new_p_g: prime and generator
         */
        Params( GeneratorParamsType &new_p_g ) : p_g( new_p_g )
        {
        }
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

        PublicKey( GeneratorParamsType &new_p_g, cpp_int pubkey_value ) :
            public_key_scalar( pubkey_value ), //
            Params( new_p_g )
        {
        }
    };
    struct PrivateKey : public PublicKey
    {
        PrivateKey( GeneratorParamsType &new_p_g, cpp_int prvkey_value ) :
            private_key_scalar( prvkey_value ),                              //
            PublicKey( new_p_g, GeneratePublicKey( new_p_g, prvkey_value ) ) //
        {
        }

        static cpp_int CreatePrivateScalar( GeneratorParamsType &new_p_g )
        {
            return PrimeNumbers::GetRandomNumber( new_p_g.first );
        }
        const cpp_int GetPrivateKeyScalar( void ) const
        {
            return private_key_scalar;
        }

    private:
        cpp_int private_key_scalar;
        cpp_int GeneratePublicKey( GeneratorParamsType &new_p_g, cpp_int prvkey_value )
        {
            return powm( new_p_g.second, prvkey_value, new_p_g.first );
        }
    };
    static CypherTextType EncryptData( PublicKey &pubkey, std::vector<uint8_t> &data_vector);
    static CypherTextType EncryptData( PublicKey &pubkey, cpp_int &data );
    static CypherTextType EncryptDataAdditive( PublicKey &pubkey, cpp_int &data);
    template <typename T>
    static T DecryptData( PrivateKey &prvkey, CypherTextType &encrypted_data );
    static cpp_int DecryptDataAdditive( PrivateKey &prvkey, CypherTextType &encrypted_data );
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

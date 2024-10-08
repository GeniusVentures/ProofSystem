/**
 * @file       ElGamalKeyGenerator.hpp
 * @brief      El Gamal key generetor header file
 * @date       2024-01-17
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _EL_GAMAL_KEY_GENERATOR_HPP_
#define _EL_GAMAL_KEY_GENERATOR_HPP_
#include <memory>
#include <nil/crypto3/detail/literals.hpp>
#include "PrimeNumbers.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::multiprecision;
class ElGamalKeyGenerator
{
    using CypherTextType = std::pair<cpp_int, cpp_int>;

public:
    constexpr static const uint256_t SAFE_PRIME = 0xf3760a5583d3509b3f72b16e3c892129fef350406f88c268f503e877e043514f_cppui256;
    constexpr static const uint256_t GENERATOR  = 0x1a2c6b6fb9971c4a993069c76258ee18ba80f778fd4d7bc07186c70e73b93004_cppui256;
    /**
     * @brief      Prime and generator parameter struct
     */
    struct Params
    {

        /**
         * @brief       Construct a new Params object
         * @param[in]   prime: prime number value
         * @param[in]   gen: generator value
         */
        Params( const cpp_int &prime, const cpp_int &gen ) : prime_number( prime ), generator( gen )
        {
        }
        const cpp_int prime_number; ///< The safe prime number used by El Gamal
        const cpp_int generator;    ///< The generator used by El Gamal
    };

    struct PublicKey : public Params
    {

        PublicKey( const Params &new_p_g, cpp_int pubkey_value ) :
            public_key_value( pubkey_value ), //
            Params( new_p_g )                 //
        {
        }
        PublicKey( cpp_int pubkey_value ) : PublicKey( Params( SAFE_PRIME, GENERATOR ), pubkey_value )
        {
        }
        const cpp_int public_key_value; ///< The value of the public key
    };
    struct PrivateKey : public PublicKey
    {
        PrivateKey( const Params &new_p_g, cpp_int prvkey_value ) :
            private_key_scalar( prvkey_value ),                              //
            PublicKey( new_p_g, GeneratePublicKey( new_p_g, prvkey_value ) ) //
        {
        }

        static cpp_int CreatePrivateScalar( const Params &new_p_g )
        {
            return PrimeNumbers::GetRandomNumber( new_p_g.prime_number );
        }
        const cpp_int GetPrivateKeyScalar( void ) const
        {
            return private_key_scalar;
        }

    private:
        const cpp_int private_key_scalar;
        cpp_int       GeneratePublicKey( const Params &new_p_g, cpp_int prvkey_value )
        {
            return powm( new_p_g.generator, prvkey_value, new_p_g.prime_number );
        }
    };
    cpp_int DecryptDataAdditive( const CypherTextType &encrypted_data );
    /**
     * @brief       Create prime number and generator
     * @return      A new set of prime number and generator @ref GeneratorParamsType 
     */
    static Params         CreateGeneratorParams( void );
    static CypherTextType EncryptData( PublicKey &pubkey, std::vector<uint8_t> &data_vector );
    static CypherTextType EncryptData( PublicKey &pubkey, const cpp_int &data );
    static CypherTextType EncryptDataAdditive( PublicKey &pubkey, const cpp_int &data );
    template <typename T>
    static T       DecryptData( const PrivateKey &prvkey, const CypherTextType &encrypted_data );
    static cpp_int DecryptDataAdditive( const PrivateKey &prvkey, const CypherTextType &encrypted_data, PrimeNumbers::BabyStepGiantStep &bsgs );

    ElGamalKeyGenerator( const Params &params );
    ElGamalKeyGenerator();
    ElGamalKeyGenerator( const Params &params, const cpp_int &private_key_value );
    ElGamalKeyGenerator( const cpp_int &private_key_value );
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
    std::shared_ptr<PrivateKey>                      private_key; ///< Private key instance
    std::shared_ptr<PublicKey>                       public_key;  ///< Public key instance
    std::shared_ptr<PrimeNumbers::BabyStepGiantStep> bsgs_instance;
};

#endif

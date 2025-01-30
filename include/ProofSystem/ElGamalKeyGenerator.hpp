/**
 * @file       ElGamal.hpp
 * @brief      El Gamal key generetor header file
 * @date       2024-01-17
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _EL_GAMAL_KEY_GENERATOR_HPP_
#define _EL_GAMAL_KEY_GENERATOR_HPP_

#include <memory>
#include <utility>

#include "ProofSystem/PrimeNumbers.hpp"
#include "nil/crypto3/multiprecision/cpp_int.hpp"
#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>

namespace KeyGenerator
{
#ifdef _USE_CRYPTO3_
    using cpp_int   = nil::crypto3::multiprecision::cpp_int;
    using uint256_t = nil::crypto3::multiprecision::uint256_t;
    using nil::crypto3::multiprecision::literals::operator""_cppui256;
#else
    using cpp_int   = nil::crypto3::multiprecision::cpp_int;
    using uint256_t = boost::multiprecision::uint256_t;
    using boost::multiprecision::literals::operator""_cppui256;
#endif

    class ElGamal
    {
        using CypherTextType = std::pair<cpp_int, cpp_int>;

    public:
        constexpr static uint256_t SAFE_PRIME = 0xf3760a5583d3509b3f72b16e3c892129fef350406f88c268f503e877e043514f_cppui256;
        constexpr static uint256_t GENERATOR  = 0x1a2c6b6fb9971c4a993069c76258ee18ba80f778fd4d7bc07186c70e73b93004_cppui256;
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
            Params( cpp_int prime, cpp_int gen ) : prime_number( std::move( prime ) ), generator( std::move( gen ) )
            {
            }
            cpp_int prime_number; ///< The safe prime number used by El Gamal
            cpp_int generator;    ///< The generator used by El Gamal
        };

        struct PublicKey
        {
            PublicKey( Params params, cpp_int pubkey_value ) : params( std::move( params ) ), public_key_value( std::move( pubkey_value ) )
            {
            }

            PublicKey( cpp_int pubkey_value ) : PublicKey( Params( SAFE_PRIME, GENERATOR ), std::move( pubkey_value ) )
            {
            }

            Params  params;
            cpp_int public_key_value; ///< The value of the public key
        };

        struct PrivateKey : public PublicKey
        {
            static cpp_int CreatePrivateScalar( const Params &new_p_g )
            {
                return PrimeNumbers::GetRandomNumber( new_p_g.prime_number );
            }

            PrivateKey( const Params &new_p_g, cpp_int prvkey_value ) :
                PublicKey( new_p_g, powm( new_p_g.generator, prvkey_value, new_p_g.prime_number ) ), private_key_scalar( std::move( prvkey_value ) )
            {
            }

            [[nodiscard]] cpp_int GetPrivateKeyScalar() const
            {
                return private_key_scalar;
            }

        private:
            const cpp_int private_key_scalar;
        };

        cpp_int DecryptDataAdditive( const CypherTextType &encrypted_data );
        /**
     * @brief       Create prime number and generator
     * @return      A new set of prime number and generator @ref GeneratorParamsType 
     */
        static Params         CreateGeneratorParams();
        static CypherTextType EncryptData( PublicKey &pubkey, std::vector<uint8_t> &data_vector );
        static CypherTextType EncryptData( PublicKey &pubkey, const cpp_int &data );
        static CypherTextType EncryptDataAdditive( PublicKey &pubkey, const cpp_int &data );
        template <typename T>
        static T       DecryptData( const PrivateKey &prvkey, const CypherTextType &encrypted_data );
        static cpp_int DecryptDataAdditive( const PrivateKey &prvkey, const CypherTextType &encrypted_data, PrimeNumbers::BabyStepGiantStep &bsgs );

        ElGamal() : ElGamal( Params( SAFE_PRIME, GENERATOR ) )
        {
        }

        ElGamal( const Params &params, cpp_int private_key_value );

        ElGamal( const Params &params ) : ElGamal( params, PrivateKey::CreatePrivateScalar( params ) )
        {
        }

        ElGamal( cpp_int private_key_value ) : ElGamal( Params( SAFE_PRIME, GENERATOR ), std::move( private_key_value ) )
        {
        }

        ~ElGamal();

        [[nodiscard]] PublicKey &GetPublicKey() const
        {
            return *public_key;
        }
        [[nodiscard]] PrivateKey &GetPrivateKey() const
        {
            return *private_key;
        }

    private:
        std::shared_ptr<PrivateKey>                      private_key; ///< Private key instance
        std::shared_ptr<PublicKey>                       public_key;  ///< Public key instance
        std::shared_ptr<PrimeNumbers::BabyStepGiantStep> bsgs_instance;
    };
}

#endif

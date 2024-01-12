/**
 * @file       BitcoinKeyGenerator.hpp
 * @brief      Bitcoin address generator header file
 * @date       2023-12-08
 * @author     Super Genius (ken@gnus.ai)
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef BITCOIN_KEY_GENERATOR_HPP
#define BITCOIN_KEY_GENERATOR_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <utility>
#include "BitcoinKeyPairParams.hpp"
#include "ext_private_key.hpp"
#include "util.hpp"
#include "ECDSAPublicKey.hpp"

using namespace nil::crypto3;

namespace bitcoin
{

    /**
     * @brief       Creates a pair of ECDSA keys and a Bitcoin address from a compressed key
     */
    class BitcoinKeyGenerator
    {
    public:
        using PubKeyPair_t = std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>;

        /**
         * @brief       Constructs a new randomly generated Bitcoin key and address
         */
        BitcoinKeyGenerator();
        /**
         * @brief       Import private key string data to construct Bitcoin key and address
         * @param[in]   private_key: Private key in string form
         */
        BitcoinKeyGenerator( const std::string &private_key );
        /**
         * @brief       Import a private key scalar value to construct Bitcoin key and address
         * @param[in]   private_key: Private key scalar value
         */
        BitcoinKeyGenerator( const scalar_field_value_type &private_key );
        /**
         * @brief       Returns the private key reference
         * @return      Reference to the private key
         */
        const pubkey::ext_private_key<policy_type> &get_private_key() const
        {
            return *privkey;
        }
        /**
         * @brief       Returns the public key reference
         * @return      Reference to the public key
         */
        const pubkey::public_key<policy_type> &get_public_key() const
        {
            return *pubkey;
        }
        /**
         * @brief       Returns the bitcoin base58 address
         * @return      Bitcoin base58 address in string form
         */
        const std::string &get_address() const
        {
            return address;
        }
        /**
         * @brief       Get the public key value used for bitcoin address derivation
         * @return      The compressed X coordinate in string form
         */
        const std::string GetUsedPubKeyValue() const
        {
            return *pubkey_info;
        }
        /**
         * @brief       Get entire key value of the public key
         * @return      The concatenated X+Y key values in string form
         */
        const std::string GetEntirePubValue() const
        {
            return pubkey_info->GetEntireKey();
        }
        /**
         * @brief       Extract the key vector data from the ECDSA public key
         * @param[in]   pub_key: Public ECDSA key
         * @return      
         */
        template <typename T>
        static T ExtractPubKeyFromField( const pubkey::public_key<policy_type> &pub_key );
        /**
         * @brief       Derive the bitcoin address from de X coordinate of the public key
         * @param[in]   pub_key_vect: The vector representation of the X coordinate of public key
         * @return      Bitcoin base58 address
         * @warning     The LSB is the 0 index and the MSB is the 31th.
         */
        static std::string DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect );

        /**
         * @brief       Create the ECDSA key pair
         * @return      Private key pointer
         */
        static std::shared_ptr<pubkey::ext_private_key<policy_type>> CreateKeys();

    private:
        static random_generator_type                          key_gen; ///< Bitcoin random key generator
        std::shared_ptr<pubkey::ext_private_key<policy_type>> privkey; ///< The ECDSA private key
        std::shared_ptr<pubkey::public_key<policy_type>>      pubkey;  ///< The ECDSA public key
        std::string                                           address; ///< The Bitcoin Address in string form

        static constexpr std::uint8_t MAIN_NETWORK_ID     = 0; ///< ID of the Main Bitcoin network
        static constexpr std::uint8_t PARITY_EVEN_ID      = 2; ///< If even, the compressed address is prepend this
        static constexpr std::uint8_t PARITY_ODD_ID       = 3; ///< If odd, the compressed address is prepend this
        static constexpr std::uint8_t CHECKSUM_SIZE_BYTES = 4; ///< Number of used checksum bytes

        /**
         * @brief       Derive the bitcoin address from own key
         * @return      the Bitcoin base58 address
         */
        std::string DeriveAddress( void );

        /**
         * @brief       Bitcoin ECDSA public key derived class
         */
        class BitcoinECDSAPublicKey : public ECDSAPublicKey
        {
            using ECDSAPublicKey::ECDSAPublicKey;

            /**
             * @brief       Implements the calculation for the public key value used for bitcoin
             * @return      The compressed X key data in string form
             */
            std::string CalcPubkeyUsedValue() const override
            {
                const std::string compressed_byte_id = ( ( X_vect.front() % 2 ) ? "03" : "02" );
                return ( compressed_byte_id + X );
            }
        };

        std::shared_ptr<BitcoinECDSAPublicKey> pubkey_info; ///< Instance of public key information class
    };
}
#endif // BITCOIN_KEY_GENERATOR_HPP

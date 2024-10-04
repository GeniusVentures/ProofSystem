/**
 * @file       EthereumKeyGenerator.hpp
 * @brief      Ethereum address generator header file
 * @date       2023-12-08
 * @author     Super Genius (ken@gnus.ai)
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef ETHEREUM_KEY_GENERATOR_HPP
#define ETHEREUM_KEY_GENERATOR_HPP

#include <string>

#include "ProofSystem/EthereumKeyPairParams.hpp"
#include "ProofSystem/ext_private_key.hpp"
#include "ProofSystem/ECDSAPublicKey.hpp"

namespace ethereum
{

    /**
     * @brief       Creates a pair of ECDSA keys and a ethereum address
     */
    class EthereumKeyGenerator
    {
    public:
        using PubKeyPair_t = std::pair<std::vector<std::uint8_t>,std::vector<std::uint8_t>>;
        /**
         * @brief       Construct a new Ethereum Key Generator
         */
        EthereumKeyGenerator();
        /**
         * @brief       Import a private key and construct a new Ethereum Key Generator
         * @param[in]   private_key: Private key in string form
         */
        EthereumKeyGenerator( const std::string &private_key );
        /**
         * @brief       Import a private key and construct a new Ethereum Key Generator
         * @param[in]   private_key: Private key in string form
         */
        EthereumKeyGenerator( const ethereum::scalar_field_value_type &private_key );
        /**
         * @brief       Getter for private key (be careful with security implications)
         * @return      Reference to the private key
         */
        const pubkey::ext_private_key<ethereum::policy_type> get_private_key() const
        {
            return *privkey;
        }
        /**
         * @brief       Getter for public key
         * @return      Reference to the public key
         */
        const pubkey::public_key<ethereum::policy_type> get_public_key() const
        {
            return *pubkey;
        }
        /**
         * @brief       Getter for the Ethereum address
         * @return      Ethereum address
         */
        const std::string &get_address() const
        {
            return address;
        }
        /**
         * @brief       Get the single public key value used by ethereum addressing
         * @return      The concatenated X and Y coordinates in string form
         */
        const std::string GetUsedPubKeyValue() const
        {
            return *pubkey_info;
        }
        /**
         * @brief       Get all key value of the public key
         * @return      The concatenated X+Y key
         */
        const std::string GetEntirePubValue() const
        {
            return pubkey_info->GetEntireKey();
        }
        /**
         * @brief       Extract the key vector data from the ECDSA public key
         * @param[in]   pub_key: Public ECDSA key
         * @return      Key data (X + Y) of the public key
         */
        template <typename T>
        static T ExtractPubKeyFromField( const pubkey::public_key<ethereum::policy_type> &pub_key );
        /**
         * @brief       Derive the ethereum address from de XY concatenated coordinates
         * @param[in]   pub_key_vect: The concatenated vector representation of both X and Y coordinates
         * @return      Ethereum address in string form
         * @warning     The LSB is the 0 index and the MSB is the 63th.
         */
        static std::string DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect );
        /**
         * @brief       Create the ECDSA key pair
         * @return      Private key pointer
         */
        static std::shared_ptr<pubkey::ext_private_key<ethereum::policy_type>> CreateKeys();

    private:
        static ethereum::random_generator_type                          key_gen; ///< Ethereum random key generator
        std::shared_ptr<pubkey::ext_private_key<ethereum::policy_type>> privkey; ///< Private key pointer
        std::shared_ptr<pubkey::public_key<ethereum::policy_type>>      pubkey;  ///< Public key pointer
        std::string                                                     address; ///< Ethereum address

        static constexpr std::string_view ADDRESS_HEADER       = "0x";                ///< Ethereum address header
        static constexpr std::size_t KECCAK_RES_VALID_POS = 24;                       ///< Start position for address derivation
        static constexpr std::size_t ADDRESS_VALID_POS    = KECCAK_RES_VALID_POS - 2; ///< Start position of the address
        static constexpr std::size_t ADDRESS_SIZE_CHARS   = 42;                       ///< Size of the address in characters
        /**
         * @brief       Derive the Ethereum address from own key
         * @return      Ethereum address in string form
         */
        std::string DeriveAddress( void );

        /**
         * @brief       Ethereum ECDSA public key derived class
         */
        class EthereumECDSAPublicKey : public ECDSAPublicKey
        {
            using ECDSAPublicKey::ECDSAPublicKey;

            /**
             * @brief       Implements the calculation for the public key value used for ethereum
             * @return      The concatenated X and Y key data in string form
             */
            std::string CalcPubkeyUsedValue() const override
            {
                return ( X + Y );
            }
        };

        std::shared_ptr<EthereumECDSAPublicKey> pubkey_info; ///< Instance of public key information class
    };

} // namespace ethereum

#endif // ETHEREUM_KEY_GENERATOR_HPP

#ifndef BITCOIN_KEY_GENERATOR_HPP
#define BITCOIN_KEY_GENERATOR_HPP

#include "BitcoinKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

namespace bitcoin
{

    /**
     * @brief       Creates a pair of ECDSA keys and a bitcoin address from a compressed key
     */
    class BitcoinKeyGenerator
    {
    public:
        /**
         * @brief       Construct a new Bitcoin Key Generator
         */
        BitcoinKeyGenerator();

        /**
         * @brief       Returns the private key reference
         * @return      Reference to the private key
         */
        const pubkey::private_key<bitcoin::policy_type> &get_private_key() const
        {
            return *privkey;
        }
        /**
         * @brief       Returns the public key reference
         * @return      Reference to the public key
         */
        const pubkey::public_key<bitcoin::policy_type> &get_public_key() const
        {
            return *pubkey;
        }
        /**
         * @brief       Returns the bitcoin base58 address in HRI string
         * @return      Bitcoin base58 address
         */
        const std::string &get_address() const
        {
            return address;
        }
        /**
         * @brief       Derive the bitcoin address from the ECDSA public key
         * @param[in]   pub_key: Public ECDSA key
         * @return      Bitcoin base58 address
         */
        static std::string DeriveAddress( const pubkey::public_key<bitcoin::policy_type> &pub_key );
        /**
         * @brief       Derive the bitcoin address from de X coordinate of the public key
         * @param[in]   pub_key_vect: The vector representation of the X coordinate of public key 
         * @return      Bitcoin base58 address
         * @warning     The LSB is the 0 index and the MSB is the 31th.
         */
        static std::string DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect );

    private:
        static bitcoin::generator_type                             key_gen;
        std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> privkey;
        std::shared_ptr<pubkey::public_key<bitcoin::policy_type>>  pubkey;
        std::string                                                address;

        static constexpr std::uint8_t MAIN_NETWORK_ID         = 0;
        static constexpr std::uint8_t PARITY_EVEN_ID          = 2;
        static constexpr std::uint8_t PARITY_ODD_ID           = 3;
        static constexpr std::uint8_t RIPEMD_160_SIZE_NIBBLES = 40;
        static constexpr std::uint8_t CHECKSUM_SIZE_BYTES     = 4;
        static constexpr std::uint8_t BASE_16                 = 16;

        /**
         * @brief       Create the ECDSA key pair
         * @return      Private key pointer 
         */
        static std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> CreateKeys();
        /**
         * @brief       Derive the bitcoin address from own key
         * @return      the Bitcoin base58 address
         */
        std::string DeriveAddress( void );
    };
}
#endif // BITCOIN_KEY_GENERATOR_HPP

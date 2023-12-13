
#ifndef ETHEREUM_KEY_GENERATOR_HPP
#define ETHEREUM_KEY_GENERATOR_HPP

#include "EthereumKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

namespace ethereum
{

    class EthereumKeyGenerator
    {
    public:
        // Constructor to generate keys on creation
        EthereumKeyGenerator();

        // Getter for private key (be careful with security implications)
        const pubkey::private_key<ethereum::policy_type> get_private_key() const
        {
            return *privkey;
        }

        // Getter for public key
        const pubkey::public_key<ethereum::policy_type> get_public_key() const
        {
            return *pubkey;
        }

        // Getter for address
        const std::string &get_address() const
        {
            return address;
        }

        /**
         * @brief       Derive the ethereum address from the ECDSA public key
         * @param[in]   pub_key: Public ECDSA key
         * @return      Ethereum address in HRI string form
         */
        static std::string DeriveAddress( const pubkey::public_key<ethereum::policy_type> &pub_key );
        /**
         * @brief       Derive the bitcoin address from de X coordinate of the public key
         * @param[in]   pub_key_vect: The vector representation of the X coordinate of public key 
         * @return      Ethereum address in HRI string form
         * @warning     The LSB is the 0 index and the MSB is the 63th.
         */
        static std::string DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect );

    private:
        static ethereum::generator_type                             key_gen;
        std::shared_ptr<pubkey::private_key<ethereum::policy_type>> privkey;
        std::shared_ptr<pubkey::public_key<ethereum::policy_type>>  pubkey;
        std::string                                                 address;

        // create the keys using static template functions
        static std::shared_ptr<pubkey::private_key<ethereum::policy_type>> CreateKeys();
        /**
         * @brief       Derive the Ethereum address from own key
         * @return      Ethereum address in HRI string form
         */
        std::string DeriveAddress( void );
    };

} // namespace ethereum

#endif // ETHEREUM_KEY_GENERATOR_HPP

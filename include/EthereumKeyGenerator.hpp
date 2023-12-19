
#ifndef ETHEREUM_KEY_GENERATOR_HPP
#define ETHEREUM_KEY_GENERATOR_HPP

#include "EthereumKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

namespace ethereum
{

    /**
     * @brief       Creates a pair of ECDSA keys and a ethereum address
     */
    class EthereumKeyGenerator
    {
    public:
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
         * @brief       Getter for private key (be careful with security implications)
         * @return      Reference to the private key 
         */
        const pubkey::private_key<ethereum::policy_type> get_private_key() const
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
         * @brief       Derive the ethereum address from the ECDSA public key
         * @param[in]   pub_key: Public ECDSA key
         * @return      Ethereum address in string form
         */
        static std::string DeriveAddress( const pubkey::public_key<ethereum::policy_type> &pub_key );
        /**
         * @brief       Derive the ethereum address from de XY concatenated coordinates
         * @param[in]   pub_key_vect: The concatenated vector representation of both X and Y coordinates
         * @return      Ethereum address in string form
         * @warning     The LSB is the 0 index and the MSB is the 63th.
         */
        static std::string DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect );

    private:
        static ethereum::generator_type                             key_gen; ///< Ethereum random key generator
        std::shared_ptr<pubkey::private_key<ethereum::policy_type>> privkey; ///< Private key pointer
        std::shared_ptr<pubkey::public_key<ethereum::policy_type>>  pubkey;  ///< Public key pointer
        std::string                                                 address; ///< Ethereum address

        /**
         * @brief       Create the ECDSA key pair
         * @return      Private key pointer
         */
        static std::shared_ptr<pubkey::private_key<ethereum::policy_type>> CreateKeys();
        /**
         * @brief       Derive the Ethereum address from own key
         * @return      Ethereum address in string form
         */
        std::string DeriveAddress( void );
    };

} // namespace ethereum

#endif // ETHEREUM_KEY_GENERATOR_HPP

#ifndef BITCOIN_KEY_GENERATOR_HPP
#define BITCOIN_KEY_GENERATOR_HPP

#include "BitcoinKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

namespace bitcoin {

    class BitcoinKeyGenerator {
    public:
        BitcoinKeyGenerator();

        const pubkey::private_key<bitcoin::policy_type> &get_private_key() const { return *privkey; }

        const pubkey::public_key<bitcoin::policy_type> &get_public_key() const { return *pubkey; }

        const std::string &get_address() const { return address; }

        static std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> CreateKeys();

        /**
         * @brief       Derive the bitcoin address from the ECDSA public key
         * @param[in]   pub_key: Public ECDSA key
         * @return      the Bitcoin base58 address
         */
        static std::string DeriveAddress(const pubkey::public_key<bitcoin::policy_type> &pub_key);
        /**
         * @brief       Derive the bitcoin address from de X coordinate of the public key
         * @param[in]   pub_key_vect: The vector representation of the X coordinate of public key 
         * @return      the Bitcoin base58 address
         * @warning     The LSB is the 0 index and the MSB is the 31th.
         */
        static std::string DeriveAddress(const std::vector<std::uint8_t> &pub_key_vect);
    private:
        static bitcoin::generator_type key_gen;
        std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> privkey;
        std::shared_ptr<pubkey::public_key<bitcoin::policy_type>> pubkey;
        std::string address;

        /**
         * @brief       Derive the bitcoin address from own key
         * @return      the Bitcoin base58 address
         */
        std::string DeriveAddress(void);
    };
}
#endif // BITCOIN_KEY_GENERATOR_HPP

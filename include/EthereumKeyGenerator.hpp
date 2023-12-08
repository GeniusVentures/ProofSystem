
#ifndef ETHEREUM_KEY_GENERATOR_HPP
#define ETHEREUM_KEY_GENERATOR_HPP

#include "EthereumKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

namespace ethereum {

    class EthereumKeyGenerator {
    public:
        // Constructor to generate keys on creation
        EthereumKeyGenerator();

        // Getter for private key (be careful with security implications)
        const pubkey::private_key<ethereum::policy_type> get_private_key() const { return *privkey; }

        // Getter for public key
        const pubkey::public_key<ethereum::policy_type> get_public_key() const { return *pubkey; }

        // Getter for address
        const std::string& get_address() const { return address; }

        // create the keys using static template functions
        static std::shared_ptr<pubkey::private_key<ethereum::policy_type>> CreateKeys();

    private:
        static ethereum::generator_type key_gen;
        std::shared_ptr<pubkey::private_key<ethereum::policy_type>> privkey;
        std::shared_ptr<pubkey::public_key<ethereum::policy_type>> pubkey;
        std::string address;
    };

} // namespace ethereum

#endif // ETHEREUM_KEY_GENERATOR_HPP

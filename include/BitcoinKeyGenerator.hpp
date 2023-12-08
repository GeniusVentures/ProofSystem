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

    private:
        static bitcoin::generator_type key_gen;
        std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> privkey;
        std::shared_ptr<pubkey::public_key<bitcoin::policy_type>> pubkey;
        std::string address;
    };
}
#endif // BITCOIN_KEY_GENERATOR_HPP

#ifndef BITCOIN_KEY_GENERATOR_HPP
#define BITCOIN_KEY_GENERATOR_HPP

#include "BitcoinKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

class BitcoinKeyGenerator {
public:
    BitcoinKeyGenerator() : privkey(key_gen()),
            pubkey(static_cast<pubkey::public_key<bitcoin::policy_type>>(privkey)) {

        /*
        // Extract address from public key
        auto hash_bytes = hashes::sha2<256>(pubkey.pubkey_data().X.data());
        address = base58::encode(hash_bytes).data();
         */
    }

    const pubkey::private_key<bitcoin::policy_type>& get_private_key() const { return privkey; }
    const pubkey::public_key<bitcoin::policy_type>& get_public_key() const { return pubkey; }
    const std::string& get_address() const { return address; }

private:
    bitcoin::generator_type key_gen;
    pubkey::private_key<bitcoin::policy_type> privkey;
    pubkey::public_key<bitcoin::policy_type> pubkey;
    std::string address;
};

#endif // BITCOIN_KEY_GENERATOR_HPP

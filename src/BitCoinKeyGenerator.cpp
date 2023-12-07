#ifndef BITCOIN_KEY_GENERATOR_HPP
#define BITCOIN_KEY_GENERATOR_HPP

#include "nil/crypto3/codec/base.hpp"
#include "BitcoinKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::codec;

class BitcoinKeyGenerator {
public:
    BitcoinKeyGenerator() {
        // Generate private key
        privkey.generate();

        // Generate public key from private key
        pubkey = privkey.generate_public_key();

        // Extract address from public key
        auto hash_bytes = hashes::sha2<256>(pubkey.pubkey_data().X.data());
        address = base58::encode(hash_bytes).data();
    }

    const pubkey::private_key<bitcoin::policy_type>& get_private_key() const { return privkey; }
    const pubkey::public_key<bitcoin::policy_type>& get_public_key() const { return pubkey; }
    const std::string& get_address() const { return address; }

private:
    pubkey::private_key<bitcoin::policy_type> privkey;
    pubkey::public_key<bitcoin::policy_type> pubkey;
    std::string address;
};

#endif // BITCOIN_KEY_GENERATOR_HPP

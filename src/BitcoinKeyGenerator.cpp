//
// Created by Super Genius on 12/7/23.
//
#include "BitcoinKeyGenerator.hpp"

namespace bitcoin {

    bitcoin::generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator() {

        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey = std::make_unique<pubkey::public_key<bitcoin::policy_type>>(*privkey);

        /*
        // Extract address from public key
        auto hash_bytes = hashes::sha2<256>(pubkey.pubkey_data().X.data());
        address = base58::encode(hash_bytes).data();
        */

    }

    std::unique_ptr<pubkey::private_key<bitcoin::policy_type>> BitcoinKeyGenerator::CreateKeys() {
        return std::make_unique<pubkey::private_key<bitcoin::policy_type>>(BitcoinKeyGenerator::key_gen());
    }
}

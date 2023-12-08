//
// Created by Super Genius on 12/7/23.
//
#include "EthereumKeyGenerator.hpp"

namespace ethereum {

    ethereum::generator_type EthereumKeyGenerator::key_gen;

    EthereumKeyGenerator::EthereumKeyGenerator() {
        privkey = EthereumKeyGenerator::CreateKeys();
        pubkey = std::make_unique<pubkey::public_key<ethereum::policy_type>>(*privkey);

        /*
            ethereum::hash_type::digest_type d = hash<ethereum::hash_type>(pubkey.pubkey_data().X.data());

            // Extract address from public key
            auto address_bytes = hashes::keccak_1600<256>(pubkey.pubkey_data().X.data());
            address = util::to_string(address_bytes);
            address = "0x" + address.substr(address.size() - 40);
            */


    }

    std::unique_ptr<pubkey::private_key<ethereum::policy_type>> EthereumKeyGenerator::CreateKeys() {
        return std::make_unique<pubkey::private_key<ethereum::policy_type>>(EthereumKeyGenerator::key_gen());
    }
}

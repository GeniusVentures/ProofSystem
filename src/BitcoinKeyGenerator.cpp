//
// Created by Super Genius on 12/7/23.
//
#include "BitcoinKeyGenerator.hpp"
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>
#include <nil/crypto3/hash/ripemd.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <vector>

namespace bitcoin {

    bitcoin::generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator() {

        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey = std::make_shared<pubkey::public_key<bitcoin::policy_type>>(*privkey);

        std::vector<std::uint8_t> x_ser(bitcoin::CurveType::g1_type<>::value_bits/8);
        nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(pubkey->pubkey_data().X, x_ser.begin(), x_ser.end());
        /**
        std::cout << "Original X "<< std::hex << pubkey->pubkey_data().X << std::endl;
        std::cout << "Size of the vector " << std::dec << x_ser.size() << std::endl;
        std::cout << "Serialized X data: ";
        for (std::size_t i = 0; i < x_ser.size(); ++i)
        {
            std::cout << std::hex << static_cast<int>(x_ser[i]);
        }
        std::cout << std::endl;
        */      
        /*
        // Extract address from public key
        auto hash_bytes = hashes::sha2<256>(pubkey.pubkey_data().X.data());
        address = base58::encode(hash_bytes).data();
        */ 

    }

    std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> BitcoinKeyGenerator::CreateKeys() {
        return std::make_shared<pubkey::private_key<bitcoin::policy_type>>(BitcoinKeyGenerator::key_gen());
    }
}

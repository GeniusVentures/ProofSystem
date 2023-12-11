//
// Created by Super Genius on 12/7/23.
//
#include "BitcoinKeyGenerator.hpp"
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>
#include <nil/crypto3/hash/ripemd.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <vector>
#include <sstream>


namespace bitcoin {

    bitcoin::generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator() {

        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey = std::make_shared<pubkey::public_key<bitcoin::policy_type>>(*privkey);

        /**
        // Extract address from public key
        //address = DeriveAddress();
        */ 

    }

    std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> BitcoinKeyGenerator::CreateKeys() {
        return std::make_shared<pubkey::private_key<bitcoin::policy_type>>(BitcoinKeyGenerator::key_gen());
    }

    std::string BitcoinKeyGenerator::DeriveAddress(const pubkey::public_key<bitcoin::policy_type> &pub_key)
    {
        std::vector<std::uint8_t> x_ser(bitcoin::CurveType::g1_type<>::value_bits/8);

        nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(pub_key.pubkey_data().X, x_ser.begin(), x_ser.end());

        return DeriveAddress(x_ser);
    }
    std::string BitcoinKeyGenerator::DeriveAddress(const std::vector<std::uint8_t> &pub_key_vect)
    {
        std::stringstream pub_key_ss;
        for (auto it = pub_key_vect.rbegin(); it != pub_key_vect.rend();++it)
        {
            pub_key_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
        }

        std::string x_compressed = ((pub_key_vect.front() %2) ? "03" : "02") + pub_key_ss.str(); 

        //std::cout << "string " << x_compressed << std::endl;

        std::array<std::uint8_t,32> sha256_hash = hash<hashes::sha2<256>>(x_compressed.begin(), x_compressed.end());
        std::array<std::uint8_t,20> ripemd160_sha256_hash = hash<hashes::ripemd160>(sha256_hash.begin(), sha256_hash.end());

        /**std::cout << "SHA 256 hashed X " << full_hash.size() << std::endl;
        for (std::size_t i = 0; i < full_hash.size(); ++i)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2) <<  static_cast<int>(full_hash[i]);
        }
        std::cout << std::endl;
        **/
        std::stringstream addr_ss;

        for (auto it = ripemd160_sha256_hash.begin(); it != ripemd160_sha256_hash.end();++it)
        {
            addr_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
        }

        std::string key_with_network_byte = "00" + addr_ss.str(); 


        //TODO - Checksum (two SHA256, get the first 4 bytes and append to key_with_network_byte)
        //TODO - Base58 
        return key_with_network_byte;
    }
    std::string BitcoinKeyGenerator::DeriveAddress(void)
    {
        return DeriveAddress(*this->pubkey);
    }
}



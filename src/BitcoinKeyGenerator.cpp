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

namespace bitcoin
{

    bitcoin::generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator()
    {

        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<bitcoin::policy_type>>( *privkey );

        /**
        // Extract address from public key
        //address = DeriveAddress();
        */
    }

    std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> BitcoinKeyGenerator::CreateKeys()
    {
        return std::make_shared<pubkey::private_key<bitcoin::policy_type>>( BitcoinKeyGenerator::key_gen() );
    }

    std::string BitcoinKeyGenerator::DeriveAddress( const pubkey::public_key<bitcoin::policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_ser( bitcoin::CurveType::g1_type<>::value_bits / 8 );

        nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pub_key.pubkey_data().X, x_ser.begin(), x_ser.end() );

        return DeriveAddress( x_ser );
    }
    std::string BitcoinKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::stringstream pub_key_ss;
        for ( auto it = pub_key_vect.rbegin(); it != pub_key_vect.rend(); ++it )
        {
            pub_key_ss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( *it );
        }

        std::string x_compressed = ( ( pub_key_vect.front() % 2 ) ? "03" : "02" ) + pub_key_ss.str();

        std::array<std::uint8_t, 32> sha256_hash           = hash<hashes::sha2<256>>( x_compressed.begin(), x_compressed.end() );
        std::string                  ripemd160_sha256_hash = hash<hashes::ripemd160>( sha256_hash.begin(), sha256_hash.end() );

        std::string key_with_network_byte = "00" + ripemd160_sha256_hash.substr( 0, 40 );

        std::array<std::uint8_t, 32> checksum = hash<hashes::sha2<256>>( key_with_network_byte.begin(), key_with_network_byte.end() );

        std::string checksum_str = hash<hashes::sha2<256>>( checksum.begin(), checksum.end() );

        std::cout << "In string " << checksum_str << std::endl;

        //TODO - Checksum (get the first 4 bytes and append to key_with_network_byte)
        //TODO - Base58
        return key_with_network_byte;
    }
    std::string BitcoinKeyGenerator::DeriveAddress( void )
    {
        return DeriveAddress( *this->pubkey );
    }
}

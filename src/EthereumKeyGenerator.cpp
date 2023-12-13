//
// Created by Super Genius on 12/7/23.
//
#include "EthereumKeyGenerator.hpp"
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>
#include <nil/crypto3/codec/adaptor/coded.hpp>
#include <nil/crypto3/codec/base.hpp>
#include <vector>
#include <sstream>

namespace ethereum
{

    ethereum::generator_type EthereumKeyGenerator::key_gen;

    EthereumKeyGenerator::EthereumKeyGenerator()
    {
        privkey = EthereumKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<ethereum::policy_type>>( *privkey );

        // Extract address from public key
        //address = DeriveAddress();
        /*
            ethereum::hash_type::digest_type d = hash<ethereum::hash_type>(pubkey.pubkey_data().X.data());

            // Extract address from public key
            auto address_bytes = hashes::keccak_1600<256>(pubkey.pubkey_data().X.data());
            address = util::to_string(address_bytes);
            address = "0x" + address.substr(address.size() - 40);
            */
    }

    std::shared_ptr<pubkey::private_key<ethereum::policy_type>> EthereumKeyGenerator::CreateKeys()
    {
        return std::make_shared<pubkey::private_key<ethereum::policy_type>>( EthereumKeyGenerator::key_gen() );
    }
    std::string EthereumKeyGenerator::DeriveAddress( const pubkey::public_key<ethereum::policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_y_ser( ( ethereum::CurveType::g1_type<>::value_bits / 8 ) * 2 );

        nil::marshalling::bincode::field<ethereum::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pub_key.pubkey_data().Y, x_y_ser.begin(), x_y_ser.begin() + x_y_ser.size() / 2 );
        nil::marshalling::bincode::field<ethereum::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pub_key.pubkey_data().X, x_y_ser.begin() + x_y_ser.size() / 2, x_y_ser.end() );

        return DeriveAddress( x_y_ser );
    }
    std::string EthereumKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::string keccak_hash = hash<hashes::keccak_1600<256>>( pub_key_vect.rbegin(), pub_key_vect.rend() );
        std::string checksum    = hash<hashes::keccak_1600<256>>( keccak_hash.begin() + 24, keccak_hash.end() );

        std::string address_w_checksum;
        for ( std::size_t i = 0; i < 40; ++i )
        {
            if ( std::isalpha( keccak_hash[i + 24] ) )
            {
                if ( static_cast<int>( checksum[i] ) > 7 )
                {
                    keccak_hash[i + 24] = std::toupper( keccak_hash[i + 24] );
                }
                else
                {
                    keccak_hash[i + 24] = std::tolower( keccak_hash[i + 24] );
                }
            }
        }

        return keccak_hash.substr( 24, 40 );
    }
    std::string EthereumKeyGenerator::DeriveAddress( void )
    {
        return DeriveAddress( *this->pubkey );
    }
}

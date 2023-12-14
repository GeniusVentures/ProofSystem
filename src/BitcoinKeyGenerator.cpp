//
// Created by Super Genius on 12/7/23.
//
#include "BitcoinKeyGenerator.hpp"
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>
#include <nil/crypto3/hash/ripemd.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>
#include <nil/crypto3/codec/adaptor/coded.hpp>
#include <nil/crypto3/codec/base.hpp>
#include <vector>
#include <sstream>

namespace bitcoin
{

    bitcoin::generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator()
    {
        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<bitcoin::policy_type>>( *privkey );

        // Extract address from public key
        address = DeriveAddress();
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
        if ( !util::isLittleEndian() )
        {
            std::reverse( x_ser.begin(), x_ser.end() );
        }

        return DeriveAddress( x_ser );
    }
    std::string BitcoinKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::vector<std::uint8_t> new_vect( pub_key_vect );
        new_vect.push_back( ( pub_key_vect.front() % 2 ) ? PARITY_ODD_ID : PARITY_EVEN_ID );

        std::array<std::uint8_t, 32> sha256_hash           = hash<hashes::sha2<256>>( new_vect.rbegin(), new_vect.rend() );
        std::vector<std::uint8_t>    ripemd160_sha256_hash = hash<hashes::ripemd160>( sha256_hash.begin(), sha256_hash.end() );

        ripemd160_sha256_hash.insert( ripemd160_sha256_hash.begin(), MAIN_NETWORK_ID );

        std::array<std::uint8_t, 32> checksum     = hash<hashes::sha2<256>>( ripemd160_sha256_hash.begin(), ripemd160_sha256_hash.end() );
        std::array<std::uint8_t, 32> checksum_str = hash<hashes::sha2<256>>( checksum.begin(), checksum.end() );

        ripemd160_sha256_hash.insert( ripemd160_sha256_hash.end(), checksum_str.begin(), checksum_str.begin() + CHECKSUM_SIZE_BYTES );

        return encode<nil::crypto3::codec::base58>( ripemd160_sha256_hash );
    }

    std::string BitcoinKeyGenerator::DeriveAddress( void )
    {
        return DeriveAddress( *this->pubkey );
    }
}

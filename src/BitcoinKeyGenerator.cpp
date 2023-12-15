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

    BitcoinKeyGenerator::BitcoinKeyGenerator( const std::string &private_key )
    {
        std::vector<std::uint8_t> priv_key_vector;
        char                     *p = const_cast<char *>( private_key.data() );
        priv_key_vector             = util::HexASCII2NumStr( p, private_key.size(), 2 );

        auto my_value = nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
            priv_key_vector.begin(), priv_key_vector.end() );

        //std::cout <<" private key imported " << std::hex << my_value.second << std::endl;

        //bitcoin::scalar_field_value_type a(0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2_cppui256);

        privkey = std::make_shared<pubkey::private_key<bitcoin::policy_type>>( my_value.second );
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

        util::AdjustEndianess( x_ser );

        return DeriveAddress( x_ser );
    }
    std::string BitcoinKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::vector<std::uint8_t> work_vect( pub_key_vect );
        work_vect.push_back( ( pub_key_vect.front() % 2 ) ? PARITY_ODD_ID : PARITY_EVEN_ID );

        work_vect = static_cast<std::vector<std::uint8_t>>( hash<hashes::sha2<256>>( work_vect.rbegin(), work_vect.rend() ) );
        work_vect = static_cast<std::vector<std::uint8_t>>( hash<hashes::ripemd160>( work_vect ) );

        work_vect.insert( work_vect.begin(), MAIN_NETWORK_ID );

        std::array<std::uint8_t, 32> checksum = hash<hashes::sha2<256>>( work_vect );
        checksum                              = hash<hashes::sha2<256>>( checksum );

        work_vect.insert( work_vect.end(), checksum.begin(), checksum.begin() + CHECKSUM_SIZE_BYTES );

        return encode<nil::crypto3::codec::base58>( work_vect );
    }

    std::string BitcoinKeyGenerator::DeriveAddress( void )
    {
        return DeriveAddress( *this->pubkey );
    }
}

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
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <vector>
#include <sstream>

namespace bitcoin
{

    bitcoin::generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator()
    {
        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<bitcoin::policy_type>>( *privkey );

        address = DeriveAddress();
    }

    BitcoinKeyGenerator::BitcoinKeyGenerator( const std::string &private_key )
    {
        std::vector<std::uint8_t> priv_key_vector;

        priv_key_vector = util::HexASCII2NumStr<std::uint8_t>( private_key.data(), private_key.size() );

        auto my_value = nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
            priv_key_vector.begin(), priv_key_vector.end() );

        privkey = std::make_shared<pubkey::private_key<bitcoin::policy_type>>( my_value.second );
        pubkey  = std::make_shared<pubkey::public_key<bitcoin::policy_type>>( *privkey );

        address = DeriveAddress();
    }

    std::shared_ptr<pubkey::private_key<bitcoin::policy_type>> BitcoinKeyGenerator::CreateKeys()
    {
        return std::make_shared<pubkey::private_key<bitcoin::policy_type>>( BitcoinKeyGenerator::key_gen() );
    }

    std::vector<std::uint8_t> BitcoinKeyGenerator::ExtractPubKeyFromField( const pubkey::public_key<bitcoin::policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_ser( bitcoin::CurveType::g1_type<>::value_bits / 8 );

        nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pub_key.pubkey_data().to_affine().X.data, x_ser.begin(), x_ser.end() );

        util::AdjustEndianess( x_ser );

        return x_ser;
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
        std::vector<std::uint8_t> pubkey_data = ExtractPubKeyFromField( *pubkey );
        std::vector<std::uint8_t> y_ser( bitcoin::CurveType::g1_type<>::value_bits / 8 );

        nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pubkey->pubkey_data().to_affine().Y.data, y_ser.begin(), y_ser.end() );

        util::AdjustEndianess( y_ser );
        pubkey_info = std::make_shared<BitcoinECDSAPublicKey>(
            pubkey_data, y_ser);
        return DeriveAddress( pubkey_data );
    }
}

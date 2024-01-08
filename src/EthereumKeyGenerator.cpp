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
#include <util.hpp>

namespace ethereum
{

    ethereum::generator_type EthereumKeyGenerator::key_gen;

    EthereumKeyGenerator::EthereumKeyGenerator()
    {
        privkey = EthereumKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<ethereum::policy_type>>( *privkey );

        address = DeriveAddress();
    }

    EthereumKeyGenerator::EthereumKeyGenerator( const std::string &private_key )
    {
        std::vector<std::uint8_t> priv_key_vector;

        priv_key_vector = util::HexASCII2NumStr<std::uint8_t>( private_key.data(), private_key.size() );

        auto my_value = nil::marshalling::bincode::field<ethereum::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
            priv_key_vector.begin(), priv_key_vector.end() );

        privkey = std::make_shared<pubkey::ext_private_key<ethereum::policy_type>>( my_value.second );
        pubkey  = std::make_shared<pubkey::public_key<ethereum::policy_type>>( *privkey );

        address = DeriveAddress();
    }

    std::shared_ptr<pubkey::ext_private_key<ethereum::policy_type>> EthereumKeyGenerator::CreateKeys()
    {
        return std::make_shared<pubkey::ext_private_key<ethereum::policy_type>>( EthereumKeyGenerator::key_gen() );
    }

    std::vector<std::uint8_t> EthereumKeyGenerator::ExtractPubKeyFromField( const pubkey::public_key<ethereum::policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_y_ser( ( ethereum::CurveType::g1_type<>::value_bits / 8 ) * 2 );

        nil::marshalling::bincode::field<ethereum::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pub_key.pubkey_data().to_affine().Y.data, x_y_ser.begin(), x_y_ser.begin() + x_y_ser.size() / 2 );

        nil::marshalling::bincode::field<ethereum::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
            pub_key.pubkey_data().to_affine().X.data, x_y_ser.begin() + x_y_ser.size() / 2, x_y_ser.end() );

        auto middle_pos = x_y_ser.begin() + x_y_ser.size() / 2;
        util::AdjustEndianess( x_y_ser, x_y_ser.begin(), middle_pos );
        util::AdjustEndianess( x_y_ser, middle_pos, x_y_ser.end() );

        return x_y_ser;
    }

    std::string EthereumKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::string keccak_hash = hash<hashes::keccak_1600<256>>( pub_key_vect.rbegin(), pub_key_vect.rend() );
        std::string checksum    = hash<hashes::keccak_1600<256>>( keccak_hash.begin() + KECCAK_RES_VALID_POS, keccak_hash.end() );

        std::string address_w_checksum;
        for ( std::size_t i = 0; i < keccak_hash.size() - KECCAK_RES_VALID_POS; ++i )
        {
            auto *p_char = &keccak_hash[i + KECCAK_RES_VALID_POS];
            if ( std::isalpha( *p_char ) )
            {
                if ( util::HexASCII2Num<std::uint8_t>( &checksum[i], 1 ) > 7 )
                {
                    *p_char = std::toupper( *p_char );
                }
                else
                {
                    *p_char = std::tolower( *p_char );
                }
            }
        }

        keccak_hash.replace( ADDRESS_VALID_POS, 2, ADDRESS_HEADER );
        return keccak_hash.substr( ADDRESS_VALID_POS, ADDRESS_SIZE_CHARS );
    }

    std::string EthereumKeyGenerator::DeriveAddress( void )
    {
        std::vector<std::uint8_t> pubkey_data = ExtractPubKeyFromField( *pubkey );
        pubkey_info                           = std::make_shared<EthereumECDSAPublicKey>(
            std::vector<std::uint8_t>( pubkey_data.data() + pubkey_data.size() / 2, pubkey_data.data() + pubkey_data.size() ),
            std::vector<std::uint8_t>( pubkey_data.data(), pubkey_data.data() + pubkey_data.size() / 2 ) );
        return DeriveAddress( pubkey_data );
    }
}

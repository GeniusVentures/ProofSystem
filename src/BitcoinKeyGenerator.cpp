/**
 * @file       BitcoinKeyGenerator.cpp
 * @brief      Bitcoin address generator source file
 * @date       2023-12-07
 * @author     Super Genius (ken@gnus.ai)
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include "ProofSystem/BitcoinKeyGenerator.hpp"

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>
#include <nil/crypto3/hash/ripemd.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/base.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;
using namespace nil::marshalling::bincode;

namespace bitcoin
{

    random_generator_type BitcoinKeyGenerator::key_gen;

    BitcoinKeyGenerator::BitcoinKeyGenerator()
    {
        privkey = BitcoinKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<policy_type>>( *privkey );

        address = DeriveAddress();
    }

    BitcoinKeyGenerator::BitcoinKeyGenerator( std::string_view private_key )
    {
        std::vector<std::uint8_t> priv_key_vector;

        priv_key_vector = util::HexASCII2NumStr<std::uint8_t>( private_key );

        auto my_value =
            field<scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>( priv_key_vector.begin(), priv_key_vector.end() );

        privkey = std::make_shared<pubkey::ext_private_key<policy_type>>( my_value.second );
        pubkey  = std::make_shared<pubkey::public_key<policy_type>>( *privkey );

        address = DeriveAddress();
    }
    BitcoinKeyGenerator::BitcoinKeyGenerator( const scalar_field_value_type &private_key )
    {

        privkey = std::make_shared<pubkey::ext_private_key<policy_type>>( private_key );
        pubkey  = std::make_shared<pubkey::public_key<policy_type>>( *privkey );

        address = DeriveAddress();
    }

    std::shared_ptr<pubkey::ext_private_key<policy_type>> BitcoinKeyGenerator::CreateKeys()
    {
        return std::make_shared<pubkey::ext_private_key<policy_type>>( BitcoinKeyGenerator::key_gen() );
    }

    template <>
    std::vector<std::uint8_t> BitcoinKeyGenerator::ExtractPubKeyFromField<std::vector<std::uint8_t>>( const pubkey::public_key<policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_y_ser( ( base_field_type::number_bits / 8 ) * 2 );

        field<base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>( pub_key.pubkey_data().to_affine().Y.data,
                                                                                             x_y_ser.begin(), x_y_ser.begin() + x_y_ser.size() / 2 );

        field<base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>( pub_key.pubkey_data().to_affine().X.data,
                                                                                             x_y_ser.begin() + x_y_ser.size() / 2, x_y_ser.end() );

        auto middle_pos = x_y_ser.begin() + x_y_ser.size() / 2;
        util::AdjustEndianess( x_y_ser, x_y_ser.begin(), middle_pos );
        util::AdjustEndianess( x_y_ser, middle_pos, x_y_ser.end() );
        return x_y_ser;
    }
    template <>
    BitcoinKeyGenerator::PubKeyPair_t
    BitcoinKeyGenerator::ExtractPubKeyFromField<BitcoinKeyGenerator::PubKeyPair_t>( const pubkey::public_key<policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_ser( base_field_type::number_bits / 8 );
        std::vector<std::uint8_t> y_ser( base_field_type::number_bits / 8 );

        field<base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>( pub_key.pubkey_data().to_affine().X.data, x_ser.begin(),
                                                                                             x_ser.end() );
        field<base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>( pub_key.pubkey_data().to_affine().Y.data, y_ser.begin(),
                                                                                             y_ser.end() );

        util::AdjustEndianess( x_ser );
        util::AdjustEndianess( y_ser );

        return std::make_pair(x_ser,y_ser);
    }

    std::string BitcoinKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::vector<std::uint8_t> work_vect( pub_key_vect );
        work_vect.push_back( ( pub_key_vect.front() % 2 ) ? PARITY_ODD_ID : PARITY_EVEN_ID );

        work_vect = static_cast<std::vector<std::uint8_t>>( hash<derivation_hash_type>( work_vect.rbegin(), work_vect.rend() ) );
        work_vect = static_cast<std::vector<std::uint8_t>>( hash<hashes::ripemd160>( work_vect ) );

        work_vect.insert( work_vect.begin(), MAIN_NETWORK_ID );

        std::array<std::uint8_t, 32> checksum = hash<derivation_hash_type>( work_vect );
        checksum                              = hash<derivation_hash_type>( checksum );

        work_vect.insert( work_vect.end(), checksum.begin(), checksum.begin() + CHECKSUM_SIZE_BYTES );

        return encode<nil::crypto3::codec::base58>( work_vect );
    }

    std::string BitcoinKeyGenerator::DeriveAddress( void )
    {
        auto pubkey_data_pair = ExtractPubKeyFromField<PubKeyPair_t>( *pubkey );

        pubkey_info = std::make_shared<BitcoinECDSAPublicKey>( std::get<0>(pubkey_data_pair), std::get<1>(pubkey_data_pair) );
        return DeriveAddress( std::get<0>(pubkey_data_pair) );
    }
}

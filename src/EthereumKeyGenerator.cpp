//
// Created by Super Genius on 12/7/23.
//
#include "ProofSystem/EthereumKeyGenerator.hpp"

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <ProofSystem/util.hpp>


using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;
using namespace nil::marshalling::bincode;

namespace ethereum
{

    random_generator_type EthereumKeyGenerator::key_gen;


    EthereumKeyGenerator::EthereumKeyGenerator()
    {
        privkey = EthereumKeyGenerator::CreateKeys();
        pubkey  = std::make_shared<pubkey::public_key<policy_type>>( *privkey );

        address = DeriveAddress();
    }

    EthereumKeyGenerator::EthereumKeyGenerator( std::string_view private_key )
    {
        std::vector<std::uint8_t> priv_key_vector;

        priv_key_vector = util::HexASCII2NumStr<std::uint8_t>( private_key );

        auto my_value =
            field<scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>( priv_key_vector.begin(), priv_key_vector.end() );
        //cppui160_type my_value = BytesToCppui160(priv_key_vector);
        //cppui160_type my_value;
        //import_bits(my_value, priv_key_vector.begin(), priv_key_vector.end());

        privkey = std::make_shared<pubkey::ext_private_key<policy_type>>( my_value );
        pubkey  = std::make_shared<pubkey::public_key<policy_type>>( *privkey );

        address = DeriveAddress();
    }
    EthereumKeyGenerator::EthereumKeyGenerator( const scalar_field_value_type &private_key )
    {

        privkey = std::make_shared<pubkey::ext_private_key<policy_type>>( private_key );
        pubkey  = std::make_shared<pubkey::public_key<policy_type>>( *privkey );

        address = DeriveAddress();
    }

    std::shared_ptr<pubkey::ext_private_key<policy_type>> EthereumKeyGenerator::CreateKeys()
    {
        return std::make_shared<pubkey::ext_private_key<policy_type>>( EthereumKeyGenerator::key_gen() );
    }

    template <>
    std::vector<std::uint8_t>
    EthereumKeyGenerator::ExtractPubKeyFromField<std::vector<std::uint8_t>>( const pubkey::public_key<policy_type> &pub_key )
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
    EthereumKeyGenerator::PubKeyPair_t
    EthereumKeyGenerator::ExtractPubKeyFromField<EthereumKeyGenerator::PubKeyPair_t>( const pubkey::public_key<policy_type> &pub_key )
    {
        std::vector<std::uint8_t> x_ser( base_field_type::number_bits / 8 );
        std::vector<std::uint8_t> y_ser( base_field_type::number_bits / 8 );

        field<base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>( pub_key.pubkey_data().to_affine().Y.data, y_ser.begin(),
                                                                                             y_ser.end() );
        field<base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>( pub_key.pubkey_data().to_affine().X.data, x_ser.begin(),
                                                                                             x_ser.end() );

        util::AdjustEndianess( y_ser );
        util::AdjustEndianess( x_ser );

        return std::make_pair( x_ser, y_ser );
    }

    std::string EthereumKeyGenerator::DeriveAddress( const std::vector<std::uint8_t> &pub_key_vect )
    {
        std::string keccak_hash = hash<derivation_hash_type>( pub_key_vect.rbegin(), pub_key_vect.rend() );
        std::string checksum    = hash<derivation_hash_type>( keccak_hash.begin() + KECCAK_RES_VALID_POS, keccak_hash.end() );

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
        std::vector<std::uint8_t> pubkey_data = ExtractPubKeyFromField<std::vector<std::uint8_t>>( *pubkey );
        pubkey_info                           = std::make_shared<EthereumECDSAPublicKey>(
            std::vector<std::uint8_t>( pubkey_data.data() + pubkey_data.size() / 2, pubkey_data.data() + pubkey_data.size() ),
            std::vector<std::uint8_t>( pubkey_data.data(), pubkey_data.data() + pubkey_data.size() / 2 ) );
        return DeriveAddress( pubkey_data );
    }
}

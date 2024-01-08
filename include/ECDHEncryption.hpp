/**
 * @file       ECDHEncryption.hpp
 * @brief       
 * @date       2024-01-05
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _ECDH_ENCRYPTION_HPP_
#define _ECDH_ENCRYPTION_HPP_
#include "Encryption.hpp"
#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/rijndael.hpp>
#include "ext_private_key.hpp"
#include "ECDSATypes.hpp"
#include "util.hpp"

using namespace nil::crypto3::pubkey;
template <typename PolicyType>
class ECDHEncryption : public Encryption
{
private:
    std::array<std::uint8_t, 32> session_secret;

public:
    std::vector<std::uint8_t> EncryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        (void)key_data;
        return nil::crypto3::encrypt<nil::crypto3::block::aes<256>>( data, session_secret );
    }

    std::vector<std::uint8_t> DecryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        (void)key_data;
        return nil::crypto3::decrypt<nil::crypto3::block::aes<256>>( data, session_secret );
    }

    ECDHEncryption( const ext_private_key<PolicyType> &own_key, const public_key<PolicyType> &foreign_key )
    {

        auto new_point = own_key * foreign_key;

        nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::array<std::uint8_t, 32>::iterator>(
            new_point.pubkey_data().to_affine().X.data, session_secret.begin(), session_secret.end() );

        util::AdjustEndianess( session_secret );

        session_secret = static_cast<std::array<std::uint8_t, 32>>( hash<hashes::sha2<256>>( session_secret.rbegin(), session_secret.rend() ) );


       // std::cout << "X original " << std::hex << foreign_key.pubkey_data().to_affine().X.data << std::endl;
       // std::cout << "new_point X original " << std::hex << new_point.pubkey_data().to_affine().X.data << std::endl;
       // std::cout << "new_point X coded ";
       // for ( auto i : session_secret )
       // {
       //     printf( "%02x", i );
       // }
       // std::cout << std::endl;
    }
};

#endif
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

using namespace nil::crypto3::pubkey;
template <typename PolicyType>
class ECDHEncryption : public Encryption
{
private:
    std::vector<std::uint8_t> session_secret;
public:
    std::vector<std::uint8_t> EncryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        return nil::crypto3::encrypt<nil::crypto3::block::aes<256>>( data, key_data );
    }

    std::vector<std::uint8_t> DecryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        return nil::crypto3::decrypt<nil::crypto3::block::aes<256>>( data, key_data );
    }

    ECDHEncryption(const ext_private_key<PolicyType> &own_key, const public_key<PolicyType> &foreign_key )
    {

        auto new_point = own_key*foreign_key;

        std::cout << "new_point X " <<  new_point.pubkey_data().to_affine().X.data << std::endl;
        std::cout << "new_point Y " <<  new_point.pubkey_data().to_affine().Y.data << std::endl;
    }

};

#endif

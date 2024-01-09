/**
 * @file       AESEncryption.hpp
 * @brief       
 * @date       2024-01-05
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _AES_ENCRYPTION_HPP_
#define _AES_ENCRYPTION_HPP_
#include "Encryption.hpp"
#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>
#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/rijndael.hpp>

class AESEncryption : public Encryption
{
private:
    /* data */
public:
    std::vector<std::uint8_t> EncryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        return nil::crypto3::encrypt<nil::crypto3::block::aes<256>>( data, key_data );
    }
    std::vector<std::uint8_t> DecryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        return nil::crypto3::decrypt<nil::crypto3::block::aes<256>>( data, key_data );
    }
};

#endif

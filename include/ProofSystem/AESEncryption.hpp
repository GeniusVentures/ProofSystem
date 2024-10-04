/**
 * @file       AESEncryption.hpp
 * @brief      AES256 @ref Encryption class file
 * @date       2024-01-05
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _AES_ENCRYPTION_HPP_
#define _AES_ENCRYPTION_HPP_

#include "ProofSystem/Encryption.hpp"

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>
#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/rijndael.hpp>

/**
 * @brief       Derived AES256 @ref Encryption class
 */
class AESEncryption : public Encryption
{

public:
    /**
     * @brief       AES256 Encrytion method
     * @param[in]   data The data to be encrypted
     * @param[in]   key_data The key to be used for encryption
     * @return      Encrypted data
     */
    std::vector<std::uint8_t> EncryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        return nil::crypto3::encrypt<nil::crypto3::block::aes<256>>( data, key_data );
    }
    /**
     * @brief       AES256 Decryption method
     * @param[in]   data The data to be decrypted
     * @param[in]   key_data The key to be used for decryption
     * @return      Decrypted data
     */
    std::vector<std::uint8_t> DecryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        return nil::crypto3::decrypt<nil::crypto3::block::aes<256>>( data, key_data );
    }
    /**
     * @brief       Checks if two @ref AESEncryption instances are equal
     * @param[in]   lhs First instance of @ref Encryption to be downcasted
     * @param[in]   rhs Second instance of @ref Encryption to be downcasted
     * @return      always return true, since no members 
     */
    bool CheckEqual( const Encryption &lhs, const Encryption &rhs ) const override
    {
        return true;
    }
}

#endif

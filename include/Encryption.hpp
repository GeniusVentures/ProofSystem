/**
 * @file       Encryption.hpp
 * @brief      Interface class header for encryption 
 * @date       2024-01-05
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _ENCRYPTION_HPP_
#define _ENCRYPTION_HPP_

#include <vector>

/**
 * @brief       Base class for Encryption scheme
 */
class Encryption
{
private:
public:
    /**
     * @brief       Virtual destructor to prevent memory leakage
     */
    virtual ~Encryption()
    {
    }
    /**
     * @brief       Interface function to Encrypt data
     * @param[in]   data The data do be encrypted
     * @param[in]   key_data The possible key to be used to encrypt
     * @return      Encrypted data vector
     */
    virtual std::vector<std::uint8_t> EncryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) = 0;
    /**
     * @brief       Interface function to Decrypt data
     * @param[in]   data The data to be decrypted
     * @param[in]   key_data The possible key to be used to decrypt
     * @return      Decrypted data vector
     */
    virtual std::vector<std::uint8_t> DecryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) = 0;
    /**
     * @brief       Interface function to check if two @ref Encryption instances are equal
     * @param[in]   lhs First instance of @ref Encryption
     * @param[in]   rhs Second instance of @ref Encryption
     * @return      true if equal, false otherwise
     */
    virtual bool CheckEqual( const Encryption &lhs, const Encryption &rhs ) const = 0;

    /**
     * @brief       Overloads equality operator to @ref CheckEqual
     * @param[in]   other The instance to be compared
     * @return      true if equal, false otherwise
     */
    const bool operator==( const Encryption &other ) const
    {
        return CheckEqual( static_cast<const Encryption &>( *this ), other );
    }
};

#endif

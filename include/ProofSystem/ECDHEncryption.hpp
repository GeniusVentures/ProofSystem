/**
 * @file       ECDHEncryption.hpp
 * @brief      Elliptic-curve Diffie-Hellman @ref Encryption header file
 * @date       2024-01-05
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _ECDH_ENCRYPTION_HPP_
#define _ECDH_ENCRYPTION_HPP_

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/rijndael.hpp>

#include "ProofSystem/Encryption.hpp"
#include "ProofSystem/ext_private_key.hpp"
#include "ProofSystem/ECDSATypes.hpp"
#include "ProofSystem/util.hpp"

/**
 * @brief       Elliptic-curve Diffie-Hellman class using AES 256 Encryption
 */
template <typename PolicyType>
class ECDHEncryption : public Encryption
{
private:
    std::array<std::uint8_t, 32> session_secret; ///< The session secret used in encryption and decryption

public:
    /**
     * @brief       Encrypts a vector of data using the session secret
     * @param[in]   data Vector of data to be encrypted
     * @param[in]   key_data Unused in this implementation
     * @return      Encrypted data vector
     */
    std::vector<std::uint8_t> EncryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        (void)key_data;
        return nil::crypto3::encrypt<nil::crypto3::block::aes<256>>( data, session_secret );
    }

    /**
     * @brief       Decrypts a vector of data using the session secret
     * @param[in]   data Vector of data to be decrypted
     * @param[in]   key_data Unused in this implementation
     * @return      Decrypted data vector
     */
    std::vector<std::uint8_t> DecryptData( std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data ) override
    {
        (void)key_data;
        return nil::crypto3::decrypt<nil::crypto3::block::aes<256>>( data, session_secret );
    }
    /**
     * @brief       Checks if two @ref ECDHEncryption instances are equal
     * @param[in]   lhs First instance of @ref Encryption to be downcasted
     * @param[in]   rhs Second instance of @ref Encryption to be downcasted
     * @return      true if session secrets are equal, false otherwise
     */
    bool CheckEqual( const Encryption &lhs, const Encryption &rhs ) const override
    {
        return ( dynamic_cast<ECDHEncryption &>( const_cast<Encryption &>( lhs ) ) ).session_secret ==
               ( dynamic_cast<ECDHEncryption &>( const_cast<Encryption &>( rhs ) ) ).session_secret;
    }

    /**
     * @brief       Constructs an ECDHEncryption object and creates a session secret
     * @param[in]   own_key The owner's private ECDSA key
     * @param[in]   foreign_key The other party's public key
     */
    ECDHEncryption( const nil::crypto3::pubkey::ext_private_key<PolicyType> &own_key,
                    const nil::crypto3::pubkey::public_key<PolicyType>      &foreign_key )
    {
        using namespace nil::crypto3::hashes;

        auto new_point = own_key * foreign_key;

        nil::marshalling::bincode::field<ecdsa_t::base_field_type>::field_element_to_bytes<std::array<std::uint8_t, 32>::iterator>(
            new_point.pubkey_data().to_affine().X.data, session_secret.begin(), session_secret.end() );

        util::AdjustEndianess( session_secret );

        session_secret = static_cast<std::array<std::uint8_t, 32>>(
            nil::crypto3::hash<ecdsa_t::hashes::sha2<256>>( session_secret.rbegin(), session_secret.rend() ) );
    }
};

#endif

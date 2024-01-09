/**
 * @file       KDFGenerator.hpp
 * @brief      Key Derivation Function Generator
 * @date       2024-01-08
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _KDF_GENERATOR_HPP_
#define _KDF_GENERATOR_HPP_

#include <vector>
#include <string>
#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include "ECDSATypes.hpp"
#include "Encryption.hpp"
#include "ECDHEncryption.hpp"
#include "ext_private_key.hpp"

/**
 * @brief       KDF Generator class
 */
template <typename PolicyType>
class KDFGenerator
{
public:
    using SignatureType = typename pubkey::public_key<PolicyType>::signature_type;
    using ECDSAPubKey   = std::string;

    /**
     * @brief       Constructs a new KDFGenerator object
     * @param[in]   own_prvt_key The private key from the owner of the instance
     * @param[in]   other_party_key The public key data from the other party
     */
    explicit KDFGenerator( const pubkey::ext_private_key<PolicyType> &own_prvt_key, const ECDSAPubKey &other_party_key );

    /**
     * @brief       Generates a shared secret with a new derived key
     * @param[in]   prvt_key Key to sign the secret
     * @param[in]   sgnus_key public key of other party
     * @return      The secret that represents the signed data and new derived key
     */
    std::string GenerateSharedSecret( const pubkey::ext_private_key<PolicyType> &prvt_key, const ECDSAPubKey &sgnus_key );

    /**
     * @brief       Checks if the shared secret is valid
     * @param[in]   signed_secret The shared secret 
     * @param[in]   prover_key 
     * @param[in]   sgnus_key 
     * @return      true if secret is valid is verified, false otherwise
     */
    ecdsa_t::scalar_field_value_type GetNewKeyFromSecret( const std::string &signed_secret, const ECDSAPubKey &prover_key, const ECDSAPubKey &sgnus_key );

private:
    std::shared_ptr<Encryption> encryptor; ///< The encryptor used by KDF to hide the shared secret

    /**
     * @brief       Builds the public key data type from the data
     * @param[in]   pubkey_data String representation of X+Y coordinates
     * @return      The ECDSA public key object 
     */
    static pubkey::public_key<PolicyType> BuildPublicKeyECDSA( const ECDSAPubKey &pubkey_data );
};

template <typename PolicyType>
KDFGenerator<PolicyType>::KDFGenerator( const pubkey::ext_private_key<PolicyType> &own_prvt_key, const ECDSAPubKey &other_party_key )
{
    encryptor = std::make_shared<ECDHEncryption<PolicyType>>( own_prvt_key, BuildPublicKeyECDSA( other_party_key ) );
}

template <typename PolicyType>
std::string KDFGenerator<PolicyType>::GenerateSharedSecret( const pubkey::ext_private_key<PolicyType> &prvt_key, const ECDSAPubKey &sgnus_key )
{
    KDFGenerator::SignatureType signed_secret = sign<PolicyType>( sgnus_key, prvt_key );
    std::vector<std::uint8_t>   signed_vector( 64 );

    nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
        std::get<0>( signed_secret ), signed_vector.begin(), signed_vector.begin() + signed_vector.size() / 2 );
    nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
        std::get<1>( signed_secret ), signed_vector.begin() + signed_vector.size() / 2, signed_vector.end() );

    std::vector<std::uint8_t> derived_key_vector =
        static_cast<std::vector<std::uint8_t>>( hash<hashes::sha2<256>>( signed_vector.begin(), signed_vector.end() ) );
    signed_vector.insert( signed_vector.end(), derived_key_vector.begin(), derived_key_vector.end() );

    std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( sgnus_key.data(), sgnus_key.size() );

    return util::to_string( encryptor->EncryptData( signed_vector, key_vector ) );
}
template <typename PolicyType>
ecdsa_t::scalar_field_value_type KDFGenerator<PolicyType>::GetNewKeyFromSecret( const std::string &signed_secret, const ECDSAPubKey &prover_key, const ECDSAPubKey &sgnus_key )
{
    std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( sgnus_key.data(), sgnus_key.size() );
    const auto                pubkey     = BuildPublicKeyECDSA( prover_key );

    std::vector<std::uint8_t> signed_vector = util::HexASCII2NumStr<std::uint8_t>( signed_secret.data(), signed_secret.size() );

    std::vector<std::uint8_t> decoded_vector = encryptor->DecryptData( signed_vector, key_vector );

    auto sign_first_part = nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
        decoded_vector.begin(), decoded_vector.begin() + 32 );
    auto sign_second_part =
        nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
            decoded_vector.begin() + 32, decoded_vector.begin() + 64 );

    //SignatureType signed_data( sign_first_part.second, sign_second_part.second );

    bool valid = static_cast<bool>( verify<PolicyType>( sgnus_key, SignatureType(sign_first_part.second, sign_second_part.second), pubkey ) );

    if (valid == false)
    {
        throw std::runtime_error ("Can't verify the signature");
    }
    auto derived_key_pair =
        nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
            decoded_vector.begin() + 64, decoded_vector.end());

    return derived_key_pair.second;
}

template <typename PolicyType>
pubkey::public_key<PolicyType> KDFGenerator<PolicyType>::BuildPublicKeyECDSA( const ECDSAPubKey &pubkey_data )
{
    auto z_data_one = pubkey::public_key<PolicyType>::g1_value_type::field_type::value_type::one();

    std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( pubkey_data.data(), pubkey_data.size() );

    auto y_data = nil::marshalling::bincode::field<ecdsa_t::base_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
        key_vector.begin(), key_vector.begin() + key_vector.size() / 2 );
    auto x_data = nil::marshalling::bincode::field<ecdsa_t::base_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
        key_vector.begin() + key_vector.size() / 2, key_vector.end() );

    return typename pubkey::public_key<PolicyType>::public_key_type( x_data.second, y_data.second, z_data_one );
}

#endif

#include <vector>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include "ext_private_key.hpp"
#include "ECDHEncryption.hpp"
#include "ECDSATypes.hpp"

template <typename PolicyType>
class KDFGenerator
{
public:
    using SignatureType   = typename pubkey::public_key<PolicyType>::signature_type;
    using SgnusPubKeyType = std::string;
    using ECDSAPubKey     = std::string;

    std::string GenerateSharedSecret( const pubkey::ext_private_key<PolicyType> &prvt_key, const SgnusPubKeyType &sgnus_key );
    bool        CheckSharedSecret( const std::string &signed_secret, const ECDSAPubKey &prover_key, const SgnusPubKeyType &sgnus_key );
    explicit KDFGenerator( const pubkey::ext_private_key<PolicyType> &own_prvt_key, const SgnusPubKeyType &other_party_key );
    ~KDFGenerator();

private:
    SignatureType secret_sign;

    std::shared_ptr<Encryption> encryptor;

    static pubkey::public_key<PolicyType> BuildPublicKeyECDSA( const ECDSAPubKey &pubkey_data );
};

template <typename PolicyType>
KDFGenerator<PolicyType>::KDFGenerator( const pubkey::ext_private_key<PolicyType> &own_prvt_key, const SgnusPubKeyType &other_party_key )
{
    encryptor = std::make_shared<ECDHEncryption<PolicyType>>( own_prvt_key, BuildPublicKeyECDSA( other_party_key ) );
}

template <typename PolicyType>
std::string KDFGenerator<PolicyType>::GenerateSharedSecret( const pubkey::ext_private_key<PolicyType> &prvt_key, const SgnusPubKeyType &sgnus_key )
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
bool KDFGenerator<PolicyType>::CheckSharedSecret( const std::string &signed_secret, const ECDSAPubKey &prover_key, const SgnusPubKeyType &sgnus_key )
{
    std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( sgnus_key.data(), sgnus_key.size() );
    const auto                pubkey     = BuildPublicKeyECDSA( prover_key );

    std::vector<std::uint8_t> signed_vector = util::HexASCII2NumStr<std::uint8_t>( signed_secret.data(), signed_secret.size() );

    std::vector<std::uint8_t> decoded_vector = encryptor->DecryptData( signed_vector, key_vector );

    auto my_first_value = nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
        decoded_vector.begin(), decoded_vector.begin() + 32 );
    auto my_second_value =
        nil::marshalling::bincode::field<ecdsa_t::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
            decoded_vector.begin() + 32, decoded_vector.begin() + 64 );

    SignatureType signed_data( my_first_value.second, my_second_value.second );

    return static_cast<bool>( verify<PolicyType>( sgnus_key, signed_data, pubkey ) );
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

template <typename PolicyType>
KDFGenerator<PolicyType>::~KDFGenerator()
{
}

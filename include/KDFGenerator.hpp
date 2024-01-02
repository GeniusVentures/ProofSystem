#include <vector>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/rijndael.hpp>
#include "BitcoinKeyGenerator.hpp"

class KDFGenerator
{
public:
    using SignatureType = typename pubkey::public_key<bitcoin::policy_type>::signature_type;
    KDFGenerator();

    static std::string GenerateSharedSecret( const pubkey::private_key<bitcoin::policy_type> &prvt_key, const std::string &pub_key_value );
    static bool          CheckSharedSecret( const std::string &signed_msg, const pubkey::private_key<bitcoin::policy_type> &prvt_key,
                                            const std::string &value );
    ~KDFGenerator();

private:
    SignatureType secret_sign;
};
std::string KDFGenerator::GenerateSharedSecret( const pubkey::private_key<bitcoin::policy_type> &prvt_key, const std::string &pub_key_value )
{
    KDFGenerator::SignatureType signed_secret = sign<bitcoin::policy_type>( pub_key_value, prvt_key );
    std::vector<std::uint8_t>   signed_vector( 64 );

    nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
        std::get<0>( signed_secret ), signed_vector.begin(), signed_vector.begin() + signed_vector.size() / 2 );
    nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
        std::get<1>( signed_secret ), signed_vector.begin() + signed_vector.size() / 2, signed_vector.end() );

    std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( pub_key_value.data(), pub_key_value.size() );

    std::string out = nil::crypto3::encrypt<nil::crypto3::block::aes<256>>( signed_vector, key_vector );
    return out;
}
bool KDFGenerator::CheckSharedSecret( const std::string &signed_msg, const pubkey::private_key<bitcoin::policy_type> &prvt_key,
                                      const std::string &value )
{
    std::vector<std::uint8_t> key_vector = util::HexASCII2NumStr<std::uint8_t>( value.data(), value.size() );
    const auto               &pubkey     = static_cast<pubkey::public_key<bitcoin::policy_type>>( prvt_key );

    std::vector<std::uint8_t> signed_vector = util::HexASCII2NumStr<std::uint8_t>( signed_msg.data(), signed_msg.size() );
    std::reverse(signed_vector.begin(),signed_vector.end());

    std::cout << std::endl;
    std::vector<std::uint8_t> decrypted_string = nil::crypto3::decrypt<nil::crypto3::block::aes<256>>( signed_vector, key_vector );

    auto my_first_value = nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
        decrypted_string.begin(), decrypted_string.begin() + decrypted_string.size() / 2 );
    auto my_second_value = nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_from_bytes<std::vector<std::uint8_t>::iterator>(
        decrypted_string.begin() + decrypted_string.size() / 2, decrypted_string.end() );

    SignatureType signed_data(my_first_value.second,my_second_value.second);
    return static_cast<bool>( verify<bitcoin::policy_type>( value, signed_data, pubkey ) );
}
KDFGenerator::KDFGenerator()
{
}

KDFGenerator::~KDFGenerator()
{
}

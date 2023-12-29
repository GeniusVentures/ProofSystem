#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/encrypt.hpp>
#include "BitcoinKeyGenerator.hpp"

class KDFGenerator
{
public:
    using SignatureType = typename pubkey::public_key<bitcoin::policy_type>::signature_type ;
    KDFGenerator();
    KDFGenerator( const pubkey::public_key<bitcoin::policy_type>::signature_type &imported_secret, const std::string &senders_key,
                  const std::string &pub_key_own_value );

    static SignatureType GenerateSharedSecret( const pubkey::private_key<bitcoin::policy_type> &prvt_key, const std::string &pub_key_value );
    static bool          CheckSharedSecret( const SignatureType &signed_msg, const pubkey::private_key<bitcoin::policy_type> &prvt_key,
                                            const std::string &value );
    ~KDFGenerator();
private:
    SignatureType secret_sign;

};
KDFGenerator::SignatureType KDFGenerator::GenerateSharedSecret( const pubkey::private_key<bitcoin::policy_type> &prvt_key,
                                                                const std::string                                &pub_key_value )
{
    return sign<bitcoin::policy_type>( pub_key_value, prvt_key );
}
bool KDFGenerator::CheckSharedSecret( const SignatureType &signed_msg, const pubkey::private_key<bitcoin::policy_type> &prvt_key,
                                      const std::string &value )
{
    const auto &pubkey = static_cast<pubkey::public_key<bitcoin::policy_type>>( prvt_key );

    return static_cast<bool>( verify<bitcoin::policy_type>( value, signed_msg, pubkey ) );
}
KDFGenerator::KDFGenerator()
{
}

KDFGenerator::~KDFGenerator()
{
}

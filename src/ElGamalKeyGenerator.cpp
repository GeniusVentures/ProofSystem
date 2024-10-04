/**
 * @file       ElGamalKeyGenerator.cpp
 * @brief      Source file of El Gamal Key Generator module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include "ProofSystem/ElGamalKeyGenerator.hpp"
#include "ProofSystem/Crypto3Util.hpp"

using namespace KeyGenerator;

ElGamal::ElGamal( const ElGamal::Params &params )
{
    private_key   = std::make_shared<PrivateKey>( params, PrivateKey::CreatePrivateScalar( params ) );
    public_key    = std::make_shared<PublicKey>( *private_key );
    bsgs_instance = std::make_shared<PrimeNumbers::BabyStepGiantStep>( params.prime_number, params.generator );
}
ElGamal::ElGamal() : ElGamal( ElGamal::Params( SAFE_PRIME, GENERATOR ) )
{
}
ElGamal::ElGamal( const ElGamal::Params &params, const cpp_int &private_key_value )
{
    private_key   = std::make_shared<PrivateKey>( params, private_key_value );
    public_key    = std::make_shared<PublicKey>( *private_key );
    bsgs_instance = std::make_shared<PrimeNumbers::BabyStepGiantStep>( params.prime_number, params.generator );
}
ElGamal::ElGamal( const cpp_int &private_key_value ) : ElGamal( ElGamal::Params( SAFE_PRIME, GENERATOR ), private_key_value )
{
}

ElGamal::~ElGamal() = default;

ElGamal::CypherTextType ElGamal::EncryptData( PublicKey &pubkey, std::vector<uint8_t> &data_vector )
{
    cpp_int message = Crypto3Util::BytesToCppInt( data_vector );

    return EncryptData( pubkey, message );
}
ElGamal::CypherTextType ElGamal::EncryptData( PublicKey &pubkey, const cpp_int &data )
{
    cpp_int random_value = PrimeNumbers::GetRandomNumber( pubkey.prime_number );

    cpp_int a = powm( pubkey.generator, random_value, pubkey.prime_number );
    cpp_int b = powm( pubkey.public_key_value, random_value, pubkey.prime_number );

    b *= data;
    b %= pubkey.prime_number;

    return std::make_pair( a, b );
}
ElGamal::CypherTextType ElGamal::EncryptDataAdditive( PublicKey &pubkey, const cpp_int &data )
{
    cpp_int data_to_encrypt = powm( pubkey.generator, data, pubkey.prime_number );
    return EncryptData( pubkey, data_to_encrypt );
}
template <>
cpp_int ElGamal::DecryptData( const PrivateKey &prvkey, const CypherTextType &encrypted_data )
{
    auto pubkey = static_cast<const PublicKey &>( prvkey );

    cpp_int mod_inverse = PrimeNumbers::ModInverseEuclideanDivision( encrypted_data.first, pubkey.prime_number );

    cpp_int m = powm( mod_inverse, prvkey.GetPrivateKeyScalar(), pubkey.prime_number );
    m *= encrypted_data.second;
    m %= pubkey.prime_number;

    return m;
}
template <>
std::vector<uint8_t> ElGamal::DecryptData( const PrivateKey &prvkey, const CypherTextType &encrypted_data )
{
    auto                 m      = DecryptData<cpp_int>( prvkey, encrypted_data );
    std::vector<uint8_t> retval = Crypto3Util::CppIntToBytes( m );

    return retval;
}
cpp_int ElGamal::DecryptDataAdditive( const CypherTextType &encrypted_data )
{
    return DecryptDataAdditive( *this->private_key, encrypted_data, *this->bsgs_instance );
}
cpp_int ElGamal::DecryptDataAdditive( const PrivateKey &prvkey, const CypherTextType &encrypted_data, PrimeNumbers::BabyStepGiantStep &bsgs )
{
    auto m = DecryptData<cpp_int>( prvkey, encrypted_data );
    return bsgs.SolveECDLP( m );
}

ElGamal::Params ElGamal::CreateGeneratorParams( void )
{
    cpp_int prime_number = 0;

    bool ret = PrimeNumbers::GenerateSafePrime<256>( 10, prime_number );

    if ( !ret )
    {
        throw std::runtime_error( "Prime number not found" );
    }

    cpp_int generator = 0;

    ret = PrimeNumbers::GetGeneratorFromPrime( 100, prime_number, generator );

    if ( !ret )
    {
        throw std::runtime_error( "Generator not found" );
    }

    return ElGamal::Params( prime_number, generator );
}

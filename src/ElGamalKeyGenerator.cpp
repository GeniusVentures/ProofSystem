/**
 * @file       ElGamalKeyGenerator.cpp
 * @brief      Source file of El Gamal Key Generator module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include "ElGamalKeyGenerator.hpp"
#include "Crypto3Util.hpp"

ElGamalKeyGenerator::ElGamalKeyGenerator( const ElGamalKeyGenerator::Params &params )
{
    private_key = std::make_shared<PrivateKey>( params, PrivateKey::CreatePrivateScalar( params ) );
    public_key  = std::make_shared<PublicKey>( *private_key );
}
ElGamalKeyGenerator::ElGamalKeyGenerator() : ElGamalKeyGenerator( ElGamalKeyGenerator::Params( SAFE_PRIME, GENERATOR ) )
{
    //std::cout << "private value " << std::hex << private_key->GetPrivateKeyScalar() << std::endl;
    //std::cout << "public value " << std::hex << public_key->public_key_value << std::endl;
}
ElGamalKeyGenerator::ElGamalKeyGenerator( const ElGamalKeyGenerator::Params &params, const cpp_int &private_key_value )
{
    private_key = std::make_shared<PrivateKey>( params, private_key_value );
    public_key  = std::make_shared<PublicKey>( *private_key );
}
ElGamalKeyGenerator::ElGamalKeyGenerator( const cpp_int &private_key_value ) :
    ElGamalKeyGenerator( ElGamalKeyGenerator::Params( SAFE_PRIME, GENERATOR ), private_key_value )
{
}

ElGamalKeyGenerator::~ElGamalKeyGenerator()
{
}

ElGamalKeyGenerator::CypherTextType ElGamalKeyGenerator::EncryptData( PublicKey &pubkey, std::vector<uint8_t> &data_vector )
{
    cpp_int message = Crypto3Util::BytesToCppInt( data_vector );

    return EncryptData( pubkey, message );
}
ElGamalKeyGenerator::CypherTextType ElGamalKeyGenerator::EncryptData( PublicKey &pubkey, cpp_int &data )
{
    cpp_int random_value = PrimeNumbers::GetRandomNumber( pubkey.prime_number );

    cpp_int a = powm( pubkey.generator, random_value, pubkey.prime_number );
    cpp_int b = powm( pubkey.public_key_value, random_value, pubkey.prime_number );

    b *= data;
    b %= pubkey.prime_number;

    return std::make_pair( a, b );
}
ElGamalKeyGenerator::CypherTextType ElGamalKeyGenerator::EncryptDataAdditive( PublicKey &pubkey, cpp_int &data )
{
    cpp_int data_to_encrypt = powm( pubkey.generator, data, pubkey.prime_number );
    return EncryptData( pubkey, data_to_encrypt );
}
template <>
cpp_int ElGamalKeyGenerator::DecryptData( PrivateKey &prvkey, CypherTextType &encrypted_data )
{
    auto pubkey = static_cast<PublicKey &>( prvkey );

    cpp_int mod_inverse = PrimeNumbers::ModInverseEuclideanDivision( encrypted_data.first, pubkey.prime_number );

    cpp_int m = powm( mod_inverse, prvkey.GetPrivateKeyScalar(), pubkey.prime_number );
    m *= encrypted_data.second;
    m %= pubkey.prime_number;

    return m;
}
template <>
std::vector<uint8_t> ElGamalKeyGenerator::DecryptData( PrivateKey &prvkey, CypherTextType &encrypted_data )
{
    auto                 m      = DecryptData<cpp_int>( prvkey, encrypted_data );
    std::vector<uint8_t> retval = Crypto3Util::CppIntToBytes( m );

    return retval;
}
cpp_int ElGamalKeyGenerator::DecryptDataAdditive( PrivateKey &prvkey, CypherTextType &encrypted_data, cpp_int hint_start )
{
    auto                     m        = DecryptData<cpp_int>( prvkey, encrypted_data );
    auto                     pubkey   = static_cast<PublicKey &>( prvkey );
    cpp_int                  hint_end = hint_start + 50000;
    PrimeNumbers::ECDLPTable curr_table( hint_start, hint_end, pubkey.prime_number, pubkey.generator );

    return ( curr_table.SolveECDLP( m ) );
}

ElGamalKeyGenerator::Params ElGamalKeyGenerator::CreateGeneratorParams( void )
{
    cpp_int prime_number = 0;

    bool ret = PrimeNumbers::GenerateSafePrime<256>( 10, prime_number );

    if ( ret == false )
    {
        throw std::runtime_error( "Prime number not found" );
    }

    cpp_int generator = 0;

    ret = PrimeNumbers::GetGeneratorFromPrime( 100, prime_number, generator );

    if ( ret == false )
    {
        throw std::runtime_error( "Generator not found" );
    }

    return ElGamalKeyGenerator::Params( prime_number, generator );
}

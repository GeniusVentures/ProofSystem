/**
 * @file       ElGamalKeyGenerator.cpp
 * @brief      Source file of El Gamal Key Generator module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#include "ElGamalKeyGenerator.hpp"
#include "PrimeNumbers.hpp"
#include "Crypto3Util.hpp"
#include <boost/math/common_factor_rt.hpp>
//#include "ECElGamal.hpp"
//#include "ECDSATypes.hpp"

ElGamalKeyGenerator::ElGamalKeyGenerator()
{
    auto params = CreateGeneratorParams();
    //ecdsa_t::scalar_field_value_type my_scalar = 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2_cppui256;
    //auto ecc_key = ECElGamal::PrivateKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>( my_scalar );
    //std::string value_pub = "1E7BCC70C72770DBB72FEA022E8A6D07F814D2EBE4DE9AE3F7AF75BF706902A7B73FF919898C836396A6B0C96812C3213B99372050853BD1678DA0EAD14487D7";
    //auto ecc_pubkey = ECElGamal::PublicKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>( value_pub );
    private_key = std::make_shared<PrivateKey>( params, PrivateKey::CreatePrivateScalar( params ) );
    public_key  = std::make_shared<PublicKey>( *private_key );
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

    auto    curr_params     = pubkey.GetParams();
    cpp_int random_value    = PrimeNumbers::GetRandomNumber( curr_params.first );

    cpp_int a = powm( curr_params.second, random_value, curr_params.first );
    cpp_int b = powm( pubkey.public_key_scalar, random_value, curr_params.first );

    b *= data;
    b %= curr_params.first;

    return std::make_pair( a, b );
}
ElGamalKeyGenerator::CypherTextType ElGamalKeyGenerator::EncryptDataAdditive( PublicKey &pubkey, cpp_int &data )
{
    auto    curr_params     = pubkey.GetParams();
    cpp_int data_to_encrypt = powm( curr_params.second, data, curr_params.first );
    return EncryptData( pubkey, data_to_encrypt );
}
template <>
cpp_int ElGamalKeyGenerator::DecryptData( PrivateKey &prvkey, CypherTextType &encrypted_data )
{
    auto curr_params = ( static_cast<PublicKey &>( prvkey ) ).GetParams();

    cpp_int mod_inverse = PrimeNumbers::ModInverseEuclideanDivision( encrypted_data.first, curr_params.first );

    cpp_int m = powm( mod_inverse, prvkey.GetPrivateKeyScalar(), curr_params.first );
    m *= encrypted_data.second;
    m %= curr_params.first;

    return m;
}
template <>
std::vector<uint8_t> ElGamalKeyGenerator::DecryptData( PrivateKey &prvkey, CypherTextType &encrypted_data )
{
    auto                 m      = DecryptData<cpp_int>( prvkey, encrypted_data );
    std::vector<uint8_t> retval = Crypto3Util::CppIntToBytes( m );

    return retval;
}
cpp_int ElGamalKeyGenerator::DecryptDataAdditive( PrivateKey &prvkey, CypherTextType &encrypted_data )
{
    auto m = DecryptData<cpp_int>( prvkey, encrypted_data );

    //return PrimeNumbers::BSGS::SolveECDLP(gen,m);
    return m; 
}

ElGamalKeyGenerator::GeneratorParamsType ElGamalKeyGenerator::CreateGeneratorParams( void )
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

    return std::make_pair( prime_number, generator );
}

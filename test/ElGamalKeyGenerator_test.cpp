/**
 * @file       ElGamalKeyGenerator_test.cpp
 * @brief      Module to test El Gamal Key Generation module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include <gtest/gtest.h>
#include <random>
#include "ElGamalKeyGenerator.hpp"

TEST( ElGamalKeyGeneratorTest, Initialization )
{
    // Created 'n' instances of generator and check for exception
    // Each generation can take some ms
    for ( size_t i = 0; i < 10; i++ )
    {
        try
        {
            ElGamalKeyGenerator{ ElGamalKeyGenerator::CreateGeneratorParams() };
        }
        catch ( ... )
        {
            FAIL() << "ElGamalKeyGenerator not created";
            break;
        }
    }
}
TEST( ElGamalKeyGeneratorTest, ImportKeys )
{
    ElGamalKeyGenerator key_generator( 0xb22e83584f11aa1ce949bd0daff1f976da072c60e49fdd3dc40dcb28fd9f1a62_cppui256 );
    cpp_int             pubkey_expected_value = 0x58008c145ce1d680d5157f5bd7ef883312639fb47ed0cef5dbb62676425e83a1_cppui256;

    EXPECT_EQ( key_generator.GetPublicKey().public_key_value, pubkey_expected_value );

    ElGamalKeyGenerator::PublicKey pubkey( pubkey_expected_value );

    EXPECT_EQ( key_generator.GetPublicKey().public_key_value, pubkey.public_key_value );
}
TEST( ElGamalKeyGeneratorTest, EncryptionDecryptionNum )
{
    ElGamalKeyGenerator key_generator;
    cpp_int             my_value = 0xbeadfeed;

    auto cypher = ElGamalKeyGenerator::EncryptData( key_generator.GetPublicKey(), my_value );

    auto result = ElGamalKeyGenerator::DecryptData<cpp_int>( key_generator.GetPrivateKey(), cypher );

    EXPECT_EQ( my_value, result );
}

TEST( ElGamalKeyGeneratorTest, EncryptionDecryptionShortVect )
{
    //TODO - No more than 31 bytes. Need multiple encryptions for that
    ElGamalKeyGenerator  key_generator;
    std::vector<uint8_t> my_vect( 31 );
    std::random_device   rd;
    std::mt19937         gen( rd() );
    std::fill( my_vect.begin(), my_vect.end(), gen() );

    auto cypher = ElGamalKeyGenerator::EncryptData( key_generator.GetPublicKey(), my_vect );

    std::vector<uint8_t> new_vect = ElGamalKeyGenerator::DecryptData<std::vector<uint8_t>>( key_generator.GetPrivateKey(), cypher );

    EXPECT_EQ( my_vect, new_vect );
}
TEST( ElGamalKeyGeneratorTest, MultiplicativeHomomorphism )
{
    ElGamalKeyGenerator key_generator;
    cpp_int             original_balance = 50;
    cpp_int             twice            = 2;

    auto cypher_balance = ElGamalKeyGenerator::EncryptData( key_generator.GetPublicKey(), original_balance );
    auto cypher_twice   = ElGamalKeyGenerator::EncryptData( key_generator.GetPublicKey(), twice );

    auto cypher_total = std::make_pair<cpp_int, cpp_int>( cypher_balance.first * cypher_twice.first, cypher_balance.second * cypher_twice.second );

    auto result = ElGamalKeyGenerator::DecryptData<cpp_int>( key_generator.GetPrivateKey(), cypher_total );

    EXPECT_EQ( original_balance * twice, result );
}
TEST( ElGamalKeyGeneratorTest, AdditiveHomomorphism )
{
    ElGamalKeyGenerator key_generator;
    cpp_int             original_balance = 50;
    cpp_int             two              = 2;

    auto cypher_50_exp = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), original_balance );
    auto cypher_2_exp  = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), two );

    auto cypher_total = std::make_pair<cpp_int, cpp_int>( cypher_50_exp.first * cypher_2_exp.first, cypher_50_exp.second * cypher_2_exp.second );

    auto result = ElGamalKeyGenerator::DecryptData<cpp_int>( key_generator.GetPrivateKey(), cypher_total );

    auto result_decoded = key_generator.DecryptDataAdditive( cypher_total );

    EXPECT_EQ( powm( key_generator.GetPublicKey().generator, original_balance + two, key_generator.GetPublicKey().prime_number ), result );
    EXPECT_EQ( original_balance + two, result_decoded );

    auto cypher_half_mil   = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), 1500000 );
    auto cypher_300k       = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), 300000 );
    auto cypher_1_800_calc = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), 1800000 );
    auto cypher_1_800_add =
        std::make_pair<cpp_int, cpp_int>( ( cypher_half_mil.first * cypher_300k.first ) % key_generator.GetPublicKey().prime_number,
                                          ( cypher_half_mil.second * cypher_300k.second ) % key_generator.GetPublicKey().prime_number );

    auto result_1_800      = key_generator.DecryptDataAdditive( cypher_1_800_add );
    auto result_1_800_calc = key_generator.DecryptDataAdditive( cypher_1_800_calc );

    EXPECT_EQ( result_1_800, 1800000 );
    EXPECT_EQ( result_1_800_calc, 1800000 );
}

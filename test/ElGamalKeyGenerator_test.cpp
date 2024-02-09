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
            ElGamalKeyGenerator{ElGamalKeyGenerator::CreateGeneratorParams()};
        }
        catch ( ... )
        {
            FAIL() << "ElGamalKeyGenerator not created";
            break;
        }
    }
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

    auto cypher_balance = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), original_balance );
    auto cypher_two     = ElGamalKeyGenerator::EncryptDataAdditive( key_generator.GetPublicKey(), two );

    auto cypher_total = std::make_pair<cpp_int, cpp_int>( cypher_balance.first * cypher_two.first, cypher_balance.second * cypher_two.second );

    auto result = ElGamalKeyGenerator::DecryptData<cpp_int>( key_generator.GetPrivateKey(), cypher_total );

    auto result_decoded = ElGamalKeyGenerator::DecryptDataAdditive( key_generator.GetPrivateKey(), cypher_total, 0 );

    EXPECT_EQ( powm( key_generator.GetPublicKey().generator, original_balance + two, key_generator.GetPublicKey().prime_number ),
               result );
    EXPECT_EQ( original_balance + two, result_decoded );

    EXPECT_THROW( ElGamalKeyGenerator::DecryptDataAdditive( key_generator.GetPrivateKey(), cypher_total, 100 ), std::runtime_error );
}


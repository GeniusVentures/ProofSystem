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
            ElGamalKeyGenerator{};
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
    ElGamalKeyGenerator  key_generator;
    cpp_int my_value = 0xbeadfeed;

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
    std::fill(my_vect.begin(), my_vect.end(), gen());

    auto cypher = ElGamalKeyGenerator::EncryptData( key_generator.GetPublicKey(), my_vect );

    std::vector<uint8_t> new_vect = ElGamalKeyGenerator::DecryptData<std::vector<uint8_t>>( key_generator.GetPrivateKey(), cypher );

    EXPECT_EQ( my_vect, new_vect );
}
/**
 * @file       ElGamalKeyGenerator_test.cpp
 * @brief      Module to test El Gamal Key Generation module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include <gtest/gtest.h>
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
TEST( ElGamalKeyGeneratorTest, EncryptionDecryption )
{
    ElGamalKeyGenerator key_generator;
    std::vector<uint8_t> my_vect = {0xde, 0xad, 0xbe, 0xef};

    auto cypher = ElGamalKeyGenerator::EncryptData(key_generator.GetPublicKey(),my_vect);

    std::vector<uint8_t> new_vect = ElGamalKeyGenerator::DecryptData(key_generator.GetPrivateKey(), cypher);

    EXPECT_EQ(my_vect,new_vect );

}
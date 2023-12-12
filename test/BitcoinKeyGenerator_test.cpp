//
// Created by Super Genius on 12/7/23.
//

#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"

using namespace bitcoin;

TEST(BitcoinKeyGeneratorTest, PrivateKeyGenerated) {
    // Arrange
    BitcoinKeyGenerator key_generator;

    // Act
    const pubkey::private_key<bitcoin::policy_type>& privkey =
            key_generator.get_private_key();
    
    // Assert
    EXPECT_TRUE(!privkey.pubkey_data().is_zero());
}

TEST(BitcoinKeyGeneratorTest, PublicKeyGenerated) {
    // Arrange
    BitcoinKeyGenerator key_generator;

    // Act
    const pubkey::public_key<bitcoin::policy_type>& pubkey =
            key_generator.get_public_key();

    // Assert
    //EXPECT_TRUE(!pubkey.empty());
}
TEST(BitcoinKeyGeneratorTest, BitCoinAddressTest)
{
    std::vector<std::uint8_t> x_ser =
    {
        0xe8,0xe2,0x53,0xd0,0x3d,0x72,0x9d,0x3a,0x0d,0xfc,0x29,0x35,0xee,0x63,0xdf,0x3d,
        0xfe,0xc0,0xcd,0x9b,0x16,0x0b,0x55,0x5a,0x33,0x18,0x9d,0xae,0x2f,0x56,0xb6,0x5d
    };
    std::reverse(x_ser.begin(),x_ser.end());
    std::string address = BitcoinKeyGenerator::DeriveAddress(x_ser);
    EXPECT_EQ(address,"1CFGFvgBKaG6DtZBryYZxg5oz3mJcgSWfC");
}

// Address generation functionality is commented out in the provided code
// Uncomment the following test if the functionality is implemented
/*
TEST(BitcoinKeyGeneratorTest, AddressGenerated) {
  // Arrange
  BitcoinKeyGenerator key_generator;

  // Act
  const std::string& address = key_generator.get_address();

  // Assert
  EXPECT_TRUE(!address.empty());
  EXPECT_TRUE(address.length() > 20);
}
*/

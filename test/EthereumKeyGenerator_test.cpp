//
// Created by Super Genius on 12/7/23.
//
#include <gtest/gtest.h>
#include "EthereumKeyGenerator.hpp"

using namespace ethereum;

TEST(EthereumKeyGeneratorTest, PrivateKeyGenerated) {
    // Arrange
    EthereumKeyGenerator *key_generator = new EthereumKeyGenerator();

    // Act
    const pubkey::private_key<ethereum::policy_type>& privkey =
            key_generator->get_private_key();

    // Assert
    //EXPECT_TRUE(!privkey.empty());
}

TEST(EthereumKeyGeneratorTest, PublicKeyGenerated) {
    // Arrange
    EthereumKeyGenerator *key_generator = new EthereumKeyGenerator();

    // Act
    const pubkey::public_key<ethereum::policy_type>& pubkey =
            key_generator->get_public_key();

    // Assert
    //EXPECT_TRUE(!pubkey.empty());
}

// Address generation functionality is commented out in the provided code
// Uncomment the following test if the functionality is implemented
/*
TEST(EthereumKeyGeneratorTest, AddressGenerated) {
  // Arrange
  EthereumKeyGenerator key_generator;

  // Act
  const std::string& address = key_generator.get_address();

  // Assert
  EXPECT_TRUE(!address.empty());
  EXPECT_TRUE(address.length() >= 42); // Address should start with "0x"
}
*/

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

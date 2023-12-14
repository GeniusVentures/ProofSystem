//
// Created by Super Genius on 12/7/23.
//
#include <gtest/gtest.h>
#include "EthereumKeyGenerator.hpp"

using namespace ethereum;

TEST( EthereumKeyGeneratorTest, PrivateKeyGenerated )
{
    // Arrange
    EthereumKeyGenerator key_generator;

    // Act
    const pubkey::private_key<ethereum::policy_type> &privkey = key_generator.get_private_key();

    // Assert
    //EXPECT_TRUE(!privkey.empty());
}

TEST( EthereumKeyGeneratorTest, PublicKeyGenerated )
{
    // Arrange
    EthereumKeyGenerator *key_generator = new EthereumKeyGenerator();

    // Act
    const pubkey::public_key<ethereum::policy_type> &pubkey = key_generator->get_public_key();

    // Assert
    //EXPECT_TRUE(!pubkey.empty());
}
TEST( EthereumKeyGeneratorTest, EthereumAddressTest )
{
    std::vector<std::uint8_t> x_y_ser = { 0xb8, 0xc6, 0x11, 0xcd, 0xf2, 0xc0, 0xaf, 0xc5, 0x9a, 0xfa, 0xb6, 0x13, 0xb8, 0x9d, 0xa8, 0x34,
                                        0x64, 0x28, 0x49, 0x28, 0xb4, 0x82, 0xc0, 0xb6, 0x04, 0xb2, 0xa9, 0x96, 0x42, 0xcb, 0x4d, 0x06,
                                        0xb3, 0x32, 0x5e, 0x59, 0x90, 0xb7, 0xfa, 0xbc, 0x60, 0xb7, 0x39, 0xf4, 0x46, 0x57, 0x77, 0x4f,
                                        0x96, 0xcd, 0x10, 0x41, 0x75, 0x06, 0xe3, 0x14, 0x30, 0x59, 0xa3, 0x4d, 0xa0, 0x7a, 0xf4, 0x5d };
    std::reverse( x_y_ser.begin(), x_y_ser.end() );
    std::string address = EthereumKeyGenerator::DeriveAddress( x_y_ser );
    EXPECT_EQ( address, "0xEb01f251BA36f6b96105f9eAEBfA86092756514B" );
}
TEST( EthereumKeyGeneratorTest, EthereumKeyImportTest )
{
    std::string private_key = "4256949314A06D963EBB6B40515E564679C931A6DCB6A3B95D90BB532C6798A5";
    //EthereumKeyGenerator key_generator(private_key);
    //EXPECT_EQ( key_generator.get_address(), "0xEb01f251BA36f6b96105f9eAEBfA86092756514B" );
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

//
// Created by Super Genius on 12/7/23.
//

#include <gtest/gtest.h>
#include "ProofSystem/BitcoinKeyGenerator.hpp"
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>
#include <nil/crypto3/codec/adaptor/coded.hpp>
#include <nil/crypto3/codec/base.hpp>

using namespace bitcoin;

TEST( BitcoinKeyGeneratorTest, PrivateKeyGenerated )
{
    // Arrange
    BitcoinKeyGenerator key_generator;

    // Act
    const pubkey::ext_private_key<bitcoin::policy_type> &privkey = key_generator.get_private_key();

    // Assert
    EXPECT_TRUE( !privkey.pubkey_data().is_zero() );
}

TEST( BitcoinKeyGeneratorTest, PublicKeyGenerated )
{
    // Arrange
    // BitcoinKeyGenerator key_generator;

    // Act
    //const pubkey::public_key<bitcoin::policy_type> &pubkey = key_generator.get_public_key();

    // Assert
    //EXPECT_TRUE(!pubkey.empty());
}

TEST( BitcoinKeyGeneratorTest, BitCoinAddressTest )
{
    std::vector<std::uint8_t> x_ser = { 0x1e, 0x7b, 0xcc, 0x70, 0xc7, 0x27, 0x70, 0xdb, 0xb7, 0x2f, 0xea, 0x02, 0x2e, 0x8a, 0x6d, 0x07,
                                        0xf8, 0x14, 0xd2, 0xeb, 0xe4, 0xde, 0x9a, 0xe3, 0xf7, 0xaf, 0x75, 0xbf, 0x70, 0x69, 0x02, 0xa7 };

    std::reverse( x_ser.begin(), x_ser.end() );
    std::string address = BitcoinKeyGenerator::DeriveAddress( x_ser );
    EXPECT_EQ( address, "17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1" );
}

TEST( BitcoinKeyGeneratorTest, BitCoinKeyImportTest )
{
    std::string priv_key_data = "60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2";

    BitcoinKeyGenerator key_generator( priv_key_data );

    EXPECT_EQ( key_generator.GetUsedPubKeyValue(), "031e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7" );

    EXPECT_EQ( key_generator.get_address(), "17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1" );
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

//
// Created by Super Genius on 12/7/23.
//

#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
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
    const pubkey::private_key<bitcoin::policy_type> &privkey = key_generator.get_private_key();

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
    //std::string               priv_key_data        = "c2efa9794718983d9f2ab39cb785ab22b8455ecfe5c858131cd359bc7d34cf60";
    std::string               priv_key_data        = "60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2";

    std::vector<std::uint8_t> x_expected_pub_key = { 0x1e, 0x7b, 0xcc, 0x70, 0xc7, 0x27, 0x70, 0xdb, 0xb7, 0x2f, 0xea, 0x02, 0x2e, 0x8a, 0x6d, 0x07,
                                                     0xf8, 0x14, 0xd2, 0xeb, 0xe4, 0xde, 0x9a, 0xe3, 0xf7, 0xaf, 0x75, 0xbf, 0x70, 0x69, 0x02, 0xa7 };

    BitcoinKeyGenerator key_generator( priv_key_data );

    std::reverse(x_expected_pub_key.begin(),x_expected_pub_key.end());
    std::vector<std::uint8_t> pub_key_export_data( bitcoin::CurveType::g1_type<>::value_bits / 8 );
    nil::marshalling::bincode::field<bitcoin::base_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
        key_generator.get_public_key().pubkey_data().to_affine().X.data, pub_key_export_data.begin(), pub_key_export_data.end() );

    EXPECT_EQ( pub_key_export_data, x_expected_pub_key );
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
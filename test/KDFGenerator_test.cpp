#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
#include "KDFGenerator.hpp"

using namespace bitcoin;
TEST( KDFGeneratorTest, KDFGeneratorMaster )
{
    BitcoinKeyGenerator bitcoin_keygen;

    std::string test_key = "031e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7";

    auto signed_key = KDFGenerator::GenerateSharedSecret( bitcoin_keygen.get_private_key(), test_key );

    EXPECT_EQ( signed_key.size(), 128 );
    EXPECT_TRUE( KDFGenerator::CheckSharedSecret( signed_key, bitcoin_keygen.get_private_key(), test_key ) );
    EXPECT_FALSE( KDFGenerator::CheckSharedSecret( signed_key, bitcoin_keygen.get_private_key(),
                                                   "088e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7" ) );
}
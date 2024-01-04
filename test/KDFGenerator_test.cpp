#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
#include "KDFGenerator.hpp"

using namespace bitcoin;
TEST( KDFGeneratorTest, KDFGeneratorMaster )
{
    BitcoinKeyGenerator bitcoin_keygen;

    std::string test_sgnus_key = "031e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7";
    std::string wrong_sgnus_key = "02aabbcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7";

    auto signed_key = KDFGenerator<bitcoin::policy_type>::GenerateSharedSecret( bitcoin_keygen.get_private_key(), test_sgnus_key );

    EXPECT_EQ( signed_key.size(), 192 );
    EXPECT_TRUE( KDFGenerator<bitcoin::policy_type>::CheckSharedSecret( signed_key, bitcoin_keygen.GetPublicKeyEntireValue(), test_sgnus_key ) );
    EXPECT_FALSE( KDFGenerator<bitcoin::policy_type>::CheckSharedSecret( signed_key, bitcoin_keygen.GetPublicKeyEntireValue(), wrong_sgnus_key ) );
}
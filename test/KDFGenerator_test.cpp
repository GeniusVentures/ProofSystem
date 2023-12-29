#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
#include "KDFGenerator.hpp"

using namespace bitcoin;
TEST( KDFGeneratorTest, KDFGeneratorMaster )
{
    BitcoinKeyGenerator bitcoin_keygen;

    std::string test_message = "JUST A MESSAGE";

    auto signed_key = KDFGenerator::GenerateSharedSecret(bitcoin_keygen.get_private_key(),test_message);

    EXPECT_TRUE(KDFGenerator::CheckSharedSecret(signed_key,bitcoin_keygen.get_private_key(), test_message));
    EXPECT_FALSE(KDFGenerator::CheckSharedSecret(signed_key,bitcoin_keygen.get_private_key(), "WRONG MESSAGE"));
}
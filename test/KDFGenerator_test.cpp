#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
#include "KDFGenerator.hpp"

using namespace bitcoin;
TEST( KDFGeneratorTest, KDFGeneratorMaster )
{

    BitcoinKeyGenerator bitcoin_proover("E23E08317D7AC841947EAABEB858B824284A856CC6D162AD14D38451D90A6A7B");

    BitcoinKeyGenerator bitcoin_revealer("B72E287D17D9D67AA6BA737117EB4A9E798C6C6E08996B14485682E522A0E984");
    KDFGenerator<bitcoin::policy_type> KDFInstance_Proover(bitcoin_proover.get_private_key(),bitcoin_revealer.GetEntirePubValue());
    KDFGenerator<bitcoin::policy_type> KDFInstance_Revealer(bitcoin_revealer.get_private_key(),bitcoin_proover.GetEntirePubValue());

    auto signed_key = KDFInstance_Proover.GenerateSharedSecret( bitcoin_proover.get_private_key(), bitcoin_revealer.GetEntirePubValue() );
    auto signed_key2 = KDFInstance_Revealer.GenerateSharedSecret( bitcoin_revealer.get_private_key(), bitcoin_proover.GetEntirePubValue() );

    EXPECT_EQ( signed_key.size(), 192 );
    EXPECT_EQ( signed_key2.size(), 192 );
    EXPECT_TRUE( KDFInstance_Proover.CheckSharedSecret( signed_key, bitcoin_proover.GetEntirePubValue(), bitcoin_revealer.GetEntirePubValue() ) );
    EXPECT_TRUE( KDFInstance_Revealer.CheckSharedSecret( signed_key2, bitcoin_revealer.GetEntirePubValue(), bitcoin_proover.GetEntirePubValue()  ) );
}
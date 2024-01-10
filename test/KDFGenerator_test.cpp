#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
#include "KDFGenerator.hpp"

using namespace bitcoin;
TEST( KDFGeneratorTest, KDFGeneratorSecretCreation )
{

    BitcoinKeyGenerator proover_instance;
    BitcoinKeyGenerator sgnus_instance;

    KDFGenerator<bitcoin::policy_type> KDFInstance_Proover( proover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    auto shared_secret = KDFInstance_Proover.GenerateSharedSecret( proover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_EQ( shared_secret.size(), KDFGenerator<bitcoin::policy_type>::EXPECTED_SECRET_SIZE );

    auto derived_scalar_value =
        KDFInstance_Proover.GetNewKeyFromSecret( shared_secret, proover_instance.GetEntirePubValue(), sgnus_instance.GetEntirePubValue() );
    EXPECT_NE( derived_scalar_value, 0 );
}
TEST( KDFGeneratorTest, KDFGeneratorDeterministic )
{

    BitcoinKeyGenerator proover_instance( "0110289C284E4665ADA21969A38525AC21B76D298CDBE6B28954EE3BD87E4628" );
    BitcoinKeyGenerator sgnus_instance( "9903EB9091DA5DB623140763AC443A69348A8A2CC52DC88029ACB4DD716A74E8" );

    BitcoinKeyGenerator proover_instance_copy( "0110289C284E4665ADA21969A38525AC21B76D298CDBE6B28954EE3BD87E4628" );
    BitcoinKeyGenerator sgnus_instance_copy( "9903EB9091DA5DB623140763AC443A69348A8A2CC52DC88029ACB4DD716A74E8" );

    KDFGenerator<bitcoin::policy_type> KDFInstance_orig( proover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type> KDFInstance_copy( proover_instance_copy.get_private_key(), sgnus_instance_copy.GetEntirePubValue() );

    auto secret_orig = KDFInstance_orig.GenerateSharedSecret( proover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    auto secret_copy = KDFInstance_copy.GenerateSharedSecret( proover_instance_copy.get_private_key(), sgnus_instance_copy.GetEntirePubValue() );

    EXPECT_EQ( secret_orig, secret_copy );
    EXPECT_EQ( secret_orig.size(), KDFGenerator<bitcoin::policy_type>::EXPECTED_SECRET_SIZE );

    auto scalar_orig = KDFInstance_orig.GetNewKeyFromSecret( secret_orig, proover_instance.GetEntirePubValue(), sgnus_instance.GetEntirePubValue() );
    EXPECT_NE( scalar_orig, 0 );

    auto scalar_copy =
        KDFInstance_copy.GetNewKeyFromSecret( secret_copy, proover_instance_copy.GetEntirePubValue(), sgnus_instance_copy.GetEntirePubValue() );
    EXPECT_NE( scalar_copy, 0 );

    EXPECT_EQ( scalar_orig, scalar_copy );
}
TEST( KDFGeneratorTest, KDFGeneratorECDHSessionKey )
{

    BitcoinKeyGenerator proover_instance;
    BitcoinKeyGenerator sgnus_instance;
    BitcoinKeyGenerator intruder_instance;

    KDFGenerator<bitcoin::policy_type>  KDFInstance_Proover( proover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type>  KDFInstance_Revealer( sgnus_instance.get_private_key(), proover_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type> *KDFInstance_Intruder =
        new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_TRUE( KDFInstance_Proover == KDFInstance_Revealer );
    EXPECT_FALSE( KDFInstance_Proover == ( *KDFInstance_Intruder ) );

    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), proover_instance.GetEntirePubValue() );
    EXPECT_FALSE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<bitcoin::policy_type>( sgnus_instance.get_private_key(), proover_instance.GetEntirePubValue() );
    EXPECT_TRUE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
}
TEST( KDFGeneratorTest, KDFGeneratorECDHSecurity )
{

    BitcoinKeyGenerator proover_instance;
    BitcoinKeyGenerator sgnus_instance;
    BitcoinKeyGenerator intruder_instance;

    KDFGenerator<bitcoin::policy_type>  KDFInstance_Proover( proover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type>  KDFInstance_Revealer( sgnus_instance.get_private_key(), proover_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type> *KDFInstance_Intruder =
        new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_TRUE( KDFInstance_Proover == KDFInstance_Revealer );
    EXPECT_FALSE( KDFInstance_Proover == ( *KDFInstance_Intruder ) );

    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), proover_instance.GetEntirePubValue() );
    EXPECT_FALSE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
}
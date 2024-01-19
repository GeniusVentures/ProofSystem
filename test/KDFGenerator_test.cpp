#include <gtest/gtest.h>
#include "BitcoinKeyGenerator.hpp"
#include "EthereumKeyGenerator.hpp"
#include "KDFGenerator.hpp"

using namespace bitcoin;
using namespace ethereum;

TEST( KDFGeneratorTest, KDFGeneratorBTCSecretCreation )
{

    BitcoinKeyGenerator prover_instance;
    BitcoinKeyGenerator sgnus_instance;

    KDFGenerator<bitcoin::policy_type> KDFInstance_Prover( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    auto shared_secret = KDFInstance_Prover.GenerateSharedSecret( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_EQ( shared_secret.size(), KDFGenerator<bitcoin::policy_type>::EXPECTED_SECRET_SIZE );

    auto derived_scalar_value =
        KDFInstance_Prover.GetNewKeyFromSecret( shared_secret, prover_instance.GetEntirePubValue(), sgnus_instance.GetEntirePubValue() );
    EXPECT_NE( derived_scalar_value, 0 );
}

TEST( KDFGeneratorTest, KDFGeneratorBTCDeterministic )
{

    BitcoinKeyGenerator prover_instance( "0110289C284E4665ADA21969A38525AC21B76D298CDBE6B28954EE3BD87E4628" );
    BitcoinKeyGenerator sgnus_instance( "9903EB9091DA5DB623140763AC443A69348A8A2CC52DC88029ACB4DD716A74E8" );

    BitcoinKeyGenerator prover_instance_copy( "0110289C284E4665ADA21969A38525AC21B76D298CDBE6B28954EE3BD87E4628" );
    BitcoinKeyGenerator sgnus_instance_copy( "9903EB9091DA5DB623140763AC443A69348A8A2CC52DC88029ACB4DD716A74E8" );

    KDFGenerator<bitcoin::policy_type> KDFInstance_orig( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type> KDFInstance_copy( prover_instance_copy.get_private_key(), sgnus_instance_copy.GetEntirePubValue() );

    auto secret_orig = KDFInstance_orig.GenerateSharedSecret( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    auto secret_copy = KDFInstance_copy.GenerateSharedSecret( prover_instance_copy.get_private_key(), sgnus_instance_copy.GetEntirePubValue() );

    EXPECT_EQ( secret_orig, secret_copy );
    EXPECT_EQ( secret_orig.size(), KDFGenerator<bitcoin::policy_type>::EXPECTED_SECRET_SIZE );

    auto scalar_orig = KDFInstance_orig.GetNewKeyFromSecret( secret_orig, prover_instance.GetEntirePubValue(), sgnus_instance.GetEntirePubValue() );
    EXPECT_NE( scalar_orig, 0 );

    auto scalar_copy =
        KDFInstance_copy.GetNewKeyFromSecret( secret_copy, prover_instance_copy.GetEntirePubValue(), sgnus_instance_copy.GetEntirePubValue() );
    EXPECT_NE( scalar_copy, 0 );

    EXPECT_EQ( scalar_orig, scalar_copy );
}

TEST( KDFGeneratorTest, KDFGeneratorBTC_ECDHSessionKey )
{

    BitcoinKeyGenerator prover_instance;
    BitcoinKeyGenerator sgnus_instance;
    BitcoinKeyGenerator intruder_instance;

    KDFGenerator<bitcoin::policy_type>  KDFInstance_Prover( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type>  KDFInstance_Revealer( sgnus_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type> *KDFInstance_Intruder =
        new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_TRUE( KDFInstance_Prover == KDFInstance_Revealer );
    EXPECT_FALSE( KDFInstance_Prover == ( *KDFInstance_Intruder ) );

    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    EXPECT_FALSE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<bitcoin::policy_type>( sgnus_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    EXPECT_TRUE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
}

TEST( KDFGeneratorTest, KDFGeneratorBTC_ECDHSecurity )
{

    BitcoinKeyGenerator prover_instance;
    BitcoinKeyGenerator sgnus_instance;
    BitcoinKeyGenerator intruder_instance;

    KDFGenerator<bitcoin::policy_type>  KDFInstance_Prover( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type>  KDFInstance_Revealer( sgnus_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    KDFGenerator<bitcoin::policy_type> *KDFInstance_Intruder =
        new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_TRUE( KDFInstance_Prover == KDFInstance_Revealer );
    EXPECT_FALSE( KDFInstance_Prover == ( *KDFInstance_Intruder ) );

    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<bitcoin::policy_type>( intruder_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    EXPECT_FALSE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
}

TEST( KDFGeneratorTest, KDFGeneratorNewBitcoin )
{

    BitcoinKeyGenerator prover_instance;
    BitcoinKeyGenerator sgnus_instance;

    auto        prover_key        = prover_instance.get_private_key();
    std::string sgnus_pubkey_data  = sgnus_instance.GetEntirePubValue();
    auto        sgnus_key          = sgnus_instance.get_private_key();
    std::string signer_pubkey_data = prover_instance.GetEntirePubValue();

    KDFGenerator<bitcoin::policy_type> *KDF = new KDFGenerator<bitcoin::policy_type>( prover_key, sgnus_pubkey_data );

    auto shared_secret = KDF->GenerateSharedSecret( prover_key, sgnus_pubkey_data );
    delete ( KDF );

    EXPECT_EQ( shared_secret.size(), KDFGenerator<bitcoin::policy_type>::EXPECTED_SECRET_SIZE );

    KDF = new KDFGenerator<bitcoin::policy_type>( sgnus_key, signer_pubkey_data );

    auto derived_scalar_value = KDF->GetNewKeyFromSecret( shared_secret, signer_pubkey_data, sgnus_pubkey_data );
    EXPECT_NE( derived_scalar_value, 0 );

    BitcoinKeyGenerator *newBitcoin = new BitcoinKeyGenerator( derived_scalar_value );

    EXPECT_NE( newBitcoin->get_address(), "" );
    EXPECT_NE( newBitcoin->GetUsedPubKeyValue(), "" );
    delete ( newBitcoin );
}

TEST( KDFGeneratorTest, KDFGeneratorETHSecretCreation )
{

    EthereumKeyGenerator prover_instance;
    EthereumKeyGenerator sgnus_instance;

    KDFGenerator<ethereum::policy_type> KDFInstance_Prover( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    auto shared_secret = KDFInstance_Prover.GenerateSharedSecret( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_EQ( shared_secret.size(), KDFGenerator<ethereum::policy_type>::EXPECTED_SECRET_SIZE );

    auto derived_scalar_value =
        KDFInstance_Prover.GetNewKeyFromSecret( shared_secret, prover_instance.GetEntirePubValue(), sgnus_instance.GetEntirePubValue() );
    EXPECT_NE( derived_scalar_value, 0 );
}

TEST( KDFGeneratorTest, KDFGeneratorETHDeterministic )
{

    EthereumKeyGenerator prover_instance( "0110289C284E4665ADA21969A38525AC21B76D298CDBE6B28954EE3BD87E4628" );
    EthereumKeyGenerator sgnus_instance( "9903EB9091DA5DB623140763AC443A69348A8A2CC52DC88029ACB4DD716A74E8" );

    EthereumKeyGenerator prover_instance_copy( "0110289C284E4665ADA21969A38525AC21B76D298CDBE6B28954EE3BD87E4628" );
    EthereumKeyGenerator sgnus_instance_copy( "9903EB9091DA5DB623140763AC443A69348A8A2CC52DC88029ACB4DD716A74E8" );

    KDFGenerator<ethereum::policy_type> KDFInstance_orig( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<ethereum::policy_type> KDFInstance_copy( prover_instance_copy.get_private_key(), sgnus_instance_copy.GetEntirePubValue() );

    auto secret_orig = KDFInstance_orig.GenerateSharedSecret( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    auto secret_copy = KDFInstance_copy.GenerateSharedSecret( prover_instance_copy.get_private_key(), sgnus_instance_copy.GetEntirePubValue() );

    EXPECT_EQ( secret_orig, secret_copy );
    EXPECT_EQ( secret_orig.size(), KDFGenerator<ethereum::policy_type>::EXPECTED_SECRET_SIZE );

    auto scalar_orig = KDFInstance_orig.GetNewKeyFromSecret( secret_orig, prover_instance.GetEntirePubValue(), sgnus_instance.GetEntirePubValue() );
    EXPECT_NE( scalar_orig, 0 );

    auto scalar_copy =
        KDFInstance_copy.GetNewKeyFromSecret( secret_copy, prover_instance_copy.GetEntirePubValue(), sgnus_instance_copy.GetEntirePubValue() );
    EXPECT_NE( scalar_copy, 0 );

    EXPECT_EQ( scalar_orig, scalar_copy );
}

TEST( KDFGeneratorTest, KDFGeneratorETH_ECDHSessionKey )
{

    EthereumKeyGenerator prover_instance;
    EthereumKeyGenerator sgnus_instance;
    EthereumKeyGenerator intruder_instance;

    KDFGenerator<ethereum::policy_type>  KDFInstance_Prover( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<ethereum::policy_type>  KDFInstance_Revealer( sgnus_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    KDFGenerator<ethereum::policy_type> *KDFInstance_Intruder =
        new KDFGenerator<ethereum::policy_type>( intruder_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_TRUE( KDFInstance_Prover == KDFInstance_Revealer );
    EXPECT_FALSE( KDFInstance_Prover == ( *KDFInstance_Intruder ) );

    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<ethereum::policy_type>( intruder_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    EXPECT_FALSE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<ethereum::policy_type>( sgnus_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    EXPECT_TRUE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
}

TEST( KDFGeneratorTest, KDFGeneratorETH_ECDHSecurity )
{

    EthereumKeyGenerator prover_instance;
    EthereumKeyGenerator sgnus_instance;
    EthereumKeyGenerator intruder_instance;

    KDFGenerator<ethereum::policy_type>  KDFInstance_Prover( prover_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );
    KDFGenerator<ethereum::policy_type>  KDFInstance_Revealer( sgnus_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    KDFGenerator<ethereum::policy_type> *KDFInstance_Intruder =
        new KDFGenerator<ethereum::policy_type>( intruder_instance.get_private_key(), sgnus_instance.GetEntirePubValue() );

    EXPECT_TRUE( KDFInstance_Prover == KDFInstance_Revealer );
    EXPECT_FALSE( KDFInstance_Prover == ( *KDFInstance_Intruder ) );

    delete ( KDFInstance_Intruder );
    KDFInstance_Intruder = new KDFGenerator<ethereum::policy_type>( intruder_instance.get_private_key(), prover_instance.GetEntirePubValue() );
    EXPECT_FALSE( KDFInstance_Revealer == ( *KDFInstance_Intruder ) );
    delete ( KDFInstance_Intruder );
}

TEST( KDFGeneratorTest, KDFGeneratorNewEthereum )
{

    EthereumKeyGenerator prover_instance;
    EthereumKeyGenerator sgnus_instance;

    auto        prover_key        = prover_instance.get_private_key();
    std::string sgnus_pubkey_data  = sgnus_instance.GetEntirePubValue();
    auto        sgnus_key          = sgnus_instance.get_private_key();
    std::string signer_pubkey_data = prover_instance.GetEntirePubValue();

    KDFGenerator<ethereum::policy_type> *KDF = new KDFGenerator<ethereum::policy_type>( prover_key, sgnus_pubkey_data );

    auto shared_secret = KDF->GenerateSharedSecret( prover_key, sgnus_pubkey_data );
    delete ( KDF );

    EXPECT_EQ( shared_secret.size(), KDFGenerator<ethereum::policy_type>::EXPECTED_SECRET_SIZE );

    KDF = new KDFGenerator<ethereum::policy_type>( sgnus_key, signer_pubkey_data );

    auto derived_scalar_value = KDF->GetNewKeyFromSecret( shared_secret, signer_pubkey_data, sgnus_pubkey_data );
    EXPECT_NE( derived_scalar_value, 0 );

    EthereumKeyGenerator *newEthereum = new EthereumKeyGenerator( derived_scalar_value );

    EXPECT_NE( newEthereum->get_address(), "" );
    EXPECT_NE( newEthereum->GetUsedPubKeyValue(), "" );
    delete ( newEthereum );
}

TEST( KDFGeneratorTest, KDFGeneratorCrossKeys )
{

    EthereumKeyGenerator prover_instance;
    BitcoinKeyGenerator  sgnus_instance;

    auto        prover_key        = prover_instance.get_private_key();
    std::string sgnus_pubkey_data  = sgnus_instance.GetEntirePubValue();
    auto        sgnus_key          = sgnus_instance.get_private_key();
    std::string signer_pubkey_data = prover_instance.GetEntirePubValue();

    KDFGenerator<ethereum::policy_type> *KDF = new KDFGenerator<ethereum::policy_type>( prover_key, sgnus_pubkey_data );

    auto shared_secret = KDF->GenerateSharedSecret( prover_key, sgnus_pubkey_data );

    EXPECT_EQ( shared_secret.size(), KDFGenerator<ethereum::policy_type>::EXPECTED_SECRET_SIZE );


    KDFGenerator<bitcoin::policy_type> *KDFBTC = new KDFGenerator<bitcoin::policy_type>( sgnus_key, signer_pubkey_data );

    auto derived_scalar_value = KDFBTC->GetNewKeyFromSecret( shared_secret, signer_pubkey_data, sgnus_pubkey_data );
    EXPECT_NE( derived_scalar_value, 0 );

    EthereumKeyGenerator *newEthereum = new EthereumKeyGenerator( derived_scalar_value );

    EXPECT_NE( newEthereum->get_address(), "" );
    EXPECT_NE( newEthereum->GetUsedPubKeyValue(), "" );
    delete ( newEthereum );
}

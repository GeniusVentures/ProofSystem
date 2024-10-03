/**
 * @file     TransactionVerifierCircuit_test.cpp
 * @brief    Test a Transaction circuit using a proof
 * @author   SuperGenius
 */

#include <gtest/gtest.h>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <include/TransactionVerifierCircuit.hpp>

using namespace nil::crypto3::algebra::curves;

TEST( TransactionVerifierCircuitTest, ValidateTransactionPass )
{
    // Test parameters
    uint64_t balance = 1000;
    uint64_t amount  = 500;
    //typename pallas::scalar_field_type::value_type                         balance = 1000;
    //typename pallas::scalar_field_type::value_type                         amount  = 500;
    typename pallas::template g1_type<coordinates::affine>::value_type     generator( 1, 2 );
    typename pallas::scalar_field_type::value_type                         base_seed     = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type                         provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges        = { 1000, 2000, 3000, 4000 };

    // Compute commitments
    auto balance_commitment              = generator * balance;
    auto amount_commitment               = generator * amount;
    auto expected_new_balance_commitment = generator * ( balance - amount );

    EXPECT_TRUE( ValidateTransaction( balance, amount, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment,
                                      generator, ranges, base_seed, provided_totp ) );
}

TEST( TransactionVerifierCircuitTest, ValidateTransactionFailNegativeBalance )
{
    // Test parameters
    uint64_t                                                               balance = 500;
    uint64_t                                                               amount  = 1000;
    typename pallas::template g1_type<coordinates::affine>::value_type     generator( 1, 2 );
    typename pallas::scalar_field_type::value_type                         base_seed     = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type                         provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges        = { 1000, 2000, 3000, 4000 };

    // Compute commitments
    auto balance_commitment              = generator * balance;
    auto amount_commitment               = generator * amount;
    auto expected_new_balance_commitment = generator * ( balance - amount ); // This is not valid but used to check the failure condition

    EXPECT_FALSE( ValidateTransaction( balance, amount, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment,
                                       generator, ranges, base_seed, provided_totp ) );
}

TEST( TransactionVerifierCircuitTest, ValidateTransactionFailInvalidCommitments )
{
    // Test parameters
    uint64_t                                                               balance = 1000;
    uint64_t                                                               amount  = 500;
    typename pallas::template g1_type<coordinates::affine>::value_type     generator( 1, 2 );
    typename pallas::scalar_field_type::value_type                         base_seed     = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type                         provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges        = { 1000, 2000, 3000, 4000 };

    // Compute commitments
    auto balance_commitment              = generator * balance;
    auto amount_commitment               = generator * amount;
    auto expected_new_balance_commitment = generator * ( balance - amount + 1 ); // Use an incorrect new balance commitment

    EXPECT_FALSE( ValidateTransaction( balance, amount, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment,
                                       generator, ranges, base_seed, provided_totp ) );
}

TEST( TransactionVerifierCircuitTest, ValidateTransactionPassZeroAmount )
{
    // Test parameters
    uint64_t                                                               balance = 1000;
    uint64_t                                                               amount  = 0;
    typename pallas::template g1_type<coordinates::affine>::value_type     generator( 1, 2 );
    typename pallas::scalar_field_type::value_type                         base_seed     = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type                         provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges        = { 1000, 2000, 3000, 4000 };

    // Compute commitments
    auto balance_commitment              = generator * balance;
    auto amount_commitment               = generator * amount;
    auto expected_new_balance_commitment = generator * balance;

    EXPECT_TRUE( ValidateTransaction( balance, amount, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment,
                                      generator, ranges, base_seed, provided_totp ) );
}

TEST( TransactionVerifierCircuitTest, ValidateTransactionPassExactBalance )
{
    // Test parameters
    uint64_t                                                               balance = 1000;
    uint64_t                                                               amount  = 1000;
    typename pallas::template g1_type<coordinates::affine>::value_type     generator( 1, 2 );
    typename pallas::scalar_field_type::value_type                         base_seed     = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type                         provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges        = { 1000, 2000, 3000, 4000 };

    // Compute commitments
    auto balance_commitment              = generator * balance;
    auto amount_commitment               = generator * amount;
    auto expected_new_balance_commitment = generator * 0;

    EXPECT_TRUE( ValidateTransaction( balance, amount, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment,
                                      generator, ranges, base_seed, provided_totp ) );
}
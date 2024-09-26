/**
 * @file     TransactionVerifierCircuit_test.cpp
 * @brief    Test a Transaction circuit using a proof
 * @author   SuperGenius
 */

#include <gtest/gtest.h>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <include/TransactionVerifierCircuit.hpp>

using namespace nil::crypto3::algebra::curves;

TEST(TransactionVerifierCircuitTest, ValidateTransactionPass) {
    // Test parameters
    typename pallas::scalar_field_type::value_type balance = 1000;
    typename pallas::scalar_field_type::value_type amount = 500;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);
    typename pallas::scalar_field_type::value_type base_seed = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges = {1000, 2000, 3000, 4000};

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount);
    uint64_t output_range;

    EXPECT_TRUE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, ranges, output_range, base_seed, provided_totp));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionFailNegativeBalance) {
    // Test parameters
    typename pallas::scalar_field_type::value_type balance = 500;
    typename pallas::scalar_field_type::value_type amount = 1000;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);
    typename pallas::scalar_field_type::value_type base_seed = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges = {1000, 2000, 3000, 4000};

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount); // This is not valid but used to check the failure condition
    uint64_t output_range;

    EXPECT_FALSE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, ranges, output_range, base_seed, provided_totp));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionFailInvalidCommitments) {
    // Test parameters
    typename pallas::scalar_field_type::value_type balance = 1000;
    typename pallas::scalar_field_type::value_type amount = 500;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);
    typename pallas::scalar_field_type::value_type base_seed = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges = {1000, 2000, 3000, 4000};

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount + 1); // Use an incorrect new balance commitment
    uint64_t output_range;

    EXPECT_FALSE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, ranges, output_range, base_seed, provided_totp));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionPassZeroAmount) {
    // Test parameters
    typename pallas::scalar_field_type::value_type balance = 1000;
    typename pallas::scalar_field_type::value_type amount = 0;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);
    typename pallas::scalar_field_type::value_type base_seed = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges = {1000, 2000, 3000, 4000};

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * balance;
    uint64_t output_range;

    EXPECT_TRUE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, ranges, output_range, base_seed, provided_totp));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionPassExactBalance) {
    // Test parameters
    typename pallas::scalar_field_type::value_type balance = 1000;
    typename pallas::scalar_field_type::value_type amount = 1000;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);
    typename pallas::scalar_field_type::value_type base_seed = 12345; // Example seed for TOTP
    typename pallas::scalar_field_type::value_type provided_totp = 67890; // Example provided TOTP
    std::array<typename pallas::scalar_field_type::value_type, MAX_RANGES> ranges = {1000, 2000, 3000, 4000};

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * 0;
    uint64_t output_range;

    EXPECT_TRUE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, ranges, output_range, base_seed, provided_totp));
}
/**
 * @file     TransactionVerifierCircuit_test.cpp
 * @brief    Test a Transaction circuit using a proof
 * @author   SuperGenius
 */

#include <gtest/gtest.h>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include "TransactionVerifierCircuit.hpp"

using namespace nil::crypto3::algebra::curves;

TEST(TransactionVerifierCircuitTest, ValidateTransactionPass) {
    // Test parameters
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 500;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount);

    EXPECT_TRUE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionFailNegativeBalance) {
    // Test parameters
    typename pallas::base_field_type::value_type balance = 500;
    typename pallas::base_field_type::value_type amount = 1000;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    // This is not valid but used to check the failure condition
    auto expected_new_balance_commitment = generator * (balance - amount);

    EXPECT_FALSE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionFailInvalidCommitments) {
    // Test parameters
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 500;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    // Use an incorrect new balance commitment
    auto expected_new_balance_commitment = generator * (balance - amount + 1);

    EXPECT_FALSE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionPassZeroAmount) {
    // Test parameters
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 0;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * balance;

    EXPECT_TRUE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator));
}

TEST(TransactionVerifierCircuitTest, ValidateTransactionPassExactBalance) {
    // Test parameters
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 1000;
    typename pallas::template g1_type<coordinates::affine>::value_type generator(1, 2);

    // Compute commitments
    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * 0;

    EXPECT_TRUE(ValidateTransaction(balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator));
}
/**
 * @file     MPCVerifierCircuit_test.cpp
 * @brief    Test the MPC ValidateTransaction circuit using a proof
 * @author   Your Name
 */

#include <gtest/gtest.h>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include "MPCVerifierCircuit.hpp"
#include "Requestor.hpp"
#include <iostream>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3::algebra::curves;

// Define an output operator for curve points
std::ostream& operator<<(std::ostream& os, const typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type& point) {
    // Replace with actual fields of the point
    os << "(" << point.X << ", " << point.Y << ")";
    return os;
}

// Simulate requestor setup for 11 nodes, each with 10 blocks
Requestor requestor(11, 10);

TEST(MPCVerifierCircuitTest, MPCValidateTransactionSetup) {

    auto generator = requestor.getGenerator();

    // Prepare the final aggregate from Nonce A and Nonce B
    typename pallas::template g1_type<coordinates::affine>::value_type final_aggregate = requestor.getFinalAggregate();

    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type total_random_sum = requestor.getTotalRandomSum();

    // Balance and amount parameters for testing
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 500;

    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount);

    // Debugging Outputs
    std::cout << "Total Random Sum: (" << total_random_sum.X << ", " << total_random_sum.Y << ")" << std::endl;
    std::cout << "Balance: " << balance << std::endl;
    std::cout << "Amount: " << amount << std::endl;
    std::cout << "Balance Commitment: (" << balance_commitment.X << ", " << balance_commitment.Y << ")" << std::endl;
    std::cout << "Amount Commitment: (" << amount_commitment.X << ", " << amount_commitment.Y << ")" << std::endl;
    std::cout << "Expected New Balance Commitment: (" << expected_new_balance_commitment.X << ", " << expected_new_balance_commitment.Y << ")" << std::endl;
    std::cout << "Final Aggregate: (" << final_aggregate.X << ", " << final_aggregate.Y << ")" << std::endl;

    // Validate the transaction
    EXPECT_TRUE(MPCValidateTransaction(
        total_random_sum,
        balance,
        amount,
        balance_commitment,
        amount_commitment,
        expected_new_balance_commitment,
        generator,
        final_aggregate
    ));
}

// Test for transaction failure due to negative balance
TEST(MPCVerifierCircuitTest, MPCValidateTransactionFailNegativeBalance) {
    typename pallas::base_field_type::value_type balance = 500;
    typename pallas::base_field_type::value_type amount = 1000;

    auto generator = requestor.getGenerator();

    // Prepare the final aggregate from Nonce A and Nonce B
    typename pallas::template g1_type<coordinates::affine>::value_type final_aggregate = requestor.getFinalAggregate();

    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type total_random_sum = requestor.getAggregateBaseNonce(); // Calculate total random sum

    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount);

    EXPECT_FALSE(MPCValidateTransaction(total_random_sum, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, final_aggregate));
}

// Test for invalid commitments
TEST(MPCVerifierCircuitTest, MPCValidateTransactionFailInvalidCommitments) {
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 500;

    auto generator = requestor.getGenerator();

    // Prepare the final aggregate from Nonce A and Nonce B
    typename pallas::template g1_type<coordinates::affine>::value_type final_aggregate = requestor.getFinalAggregate();

    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type total_random_sum = requestor.getAggregateBaseNonce(); // Calculate total random sum

    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * (balance - amount + 1);

    EXPECT_FALSE(MPCValidateTransaction(total_random_sum, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, final_aggregate));
}

// Test for transaction with zero amount
TEST(MPCVerifierCircuitTest, MPCValidateTransactionPassZeroAmount) {
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 0;

    auto generator = requestor.getGenerator();

    // Prepare the final aggregate from Nonce A and Nonce B
    typename pallas::template g1_type<coordinates::affine>::value_type final_aggregate = requestor.getFinalAggregate();

    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type total_random_sum = requestor.getAggregateBaseNonce(); // Calculate total random sum

    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * balance;

    EXPECT_TRUE(MPCValidateTransaction(total_random_sum, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, final_aggregate));
}

// Test for exact balance
TEST(MPCVerifierCircuitTest, MPCValidateTransactionPassExactBalance) {
    typename pallas::base_field_type::value_type balance = 1000;
    typename pallas::base_field_type::value_type amount = 1000;

    auto generator = requestor.getGenerator();

    // Prepare the final aggregate from Nonce A and Nonce B
    typename pallas::template g1_type<coordinates::affine>::value_type final_aggregate = requestor.getFinalAggregate();

    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type total_random_sum = requestor.getAggregateBaseNonce(); // Calculate total random sum

    auto balance_commitment = generator * balance;
    auto amount_commitment = generator * amount;
    auto expected_new_balance_commitment = generator * 0;

    EXPECT_TRUE(MPCValidateTransaction(total_random_sum, balance, amount, balance_commitment, amount_commitment, expected_new_balance_commitment, generator, final_aggregate));
}
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <array>

using namespace nil::crypto3::algebra::curves;

[[circuit]] bool ValidateTransaction(
    [[private_input]] typename pallas::base_field_type::value_type balance,
    [[private_input]] typename pallas::base_field_type::value_type amount,
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type balance_commitment,
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type amount_commitment,
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected_new_balance_commitment,
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type generator) {

    // Check if the new balance is non-negative
    if (balance >= amount) {

        // Compute the new balance
        typename pallas::base_field_type::value_type new_balance = balance - amount;

        // Verify that the commitments match the expected values
        bool valid_balance_commitment = (balance_commitment == (generator * balance));
        bool valid_amount_commitment = (amount_commitment == (generator * amount));
        bool valid_new_balance_commitment = (expected_new_balance_commitment == (generator * new_balance));

        // Ensure all verifications are true
        if (valid_balance_commitment && valid_amount_commitment && valid_new_balance_commitment) {
            return true;
        }
    }

    // If any check fails, return false
    return false;
}
#ifndef REQUESTOR_HPP
#define REQUESTOR_HPP

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <vector>
#include <random>

using namespace nil::crypto3::algebra::curves;

class Requestor {
public:
    Requestor(size_t num_nodes, size_t num_blocks_per_node);

    void setupNodes();

    // Updated return type for total random sum (now returns a G1 point)
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type getTotalRandomSum() const;
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type getFinalAggregate() const;

    // Getters for Nonce A and B values
    const std::vector<typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type>& getNonceA() const;
    const std::vector<typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type>& getNonceB() const;

    // get the sum of all the base nonce random values
    const typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type getAggregateBaseNonce() const;

    // get the final public generator
    const typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type& getGenerator() const;

private:
    size_t num_nodes;
    size_t num_blocks_per_node;
    std::vector<typename pallas::scalar_field_type::value_type> random_numbers;
    std::vector<typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type> nonces_a;
    std::vector<typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type> nonces_b;
    typename pallas::scalar_field_type::value_type base_nonce;

    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type final_aggregate;
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type generator; // Generator point

    void generateNoncesForNode(size_t node_number);
};

#endif // REQUESTOR_HPP
#include "Requestor.hpp"
#include <cstdio>
// Constructor
Requestor::Requestor( size_t num_nodes, size_t num_blocks_per_node ) : num_nodes( num_nodes ), num_blocks_per_node( num_blocks_per_node )
{
    // Initialize the generator point (replace with the actual generator point if known)
    generator = typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type(
        1, 2 ); // Example coordinates for the generator
    setupNodes();
}

// Setup node Nonce A and Nonce B values
void Requestor::setupNodes()
{
    std::random_device                           rd;
    std::mt19937                                 gen( rd() );
    std::uniform_int_distribution<std::uint64_t> dis( 0, 100000 ); // Random number generation
    std::uint64_t                                base_random = dis( gen );
    base_nonce                                               = typename pallas::base_field_type::value_type( base_random );
    std::uniform_int_distribution<std::uint64_t> dist2( base_random + num_blocks_per_node + num_nodes, base_random + 100000 );
    for ( size_t i = 0; i < num_nodes; ++i )
    {
        std::uint64_t random_number = dist2( gen ); // Generate a random number

        // Store the random number as a base field element
        random_numbers.push_back( typename pallas::base_field_type::value_type( random_number ) );

        // Generate Nonce A and Nonce B for each block in the node
        generateNoncesForNode( i );
    }
}

// Generate Nonces for a specific node
void Requestor::generateNoncesForNode( size_t node_number )
{

    for ( size_t block_index = 0; block_index < num_blocks_per_node; ++block_index )
    {
        // Retrieve positive and negative nonces
        auto positive_nonce = random_numbers[node_number] + base_nonce;
        auto negative_nonce = random_numbers[node_number] - base_nonce;

        // Create Nonce A and Nonce B as base field types
        nonces_a.push_back( generator * typename pallas::base_field_type::value_type( negative_nonce - node_number - block_index ) );
        nonces_b.push_back( generator * typename pallas::base_field_type::value_type( positive_nonce + node_number + block_index ) );
    }
}

// Calculate the total random sum as a G1 point
typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Requestor::getTotalRandomSum() const
{
    // Start with the identity point for the curve
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type total_sum =
        typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type(); // Identity point

    for ( const auto &num : random_numbers )
    {
        // Accumulate the total random sum as G1 points
        total_sum = total_sum + ( generator * num * 2 * num_blocks_per_node ); // Convert each number to a curve point using the generator
    }

    return total_sum; // Return the total sum as a G1 point
}

// Calculate the final aggregate
typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Requestor::getFinalAggregate() const
{
    // Initialize aggregate as the identity point
    typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type aggregate =
        typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type();

    for ( size_t i = 0; i < nonces_a.size(); i += num_blocks_per_node )
    {
        // Aggregate Nonce A and Nonce B values in the context of the curve

        for ( size_t block_index = 0; block_index < num_blocks_per_node; ++block_index )
        {
            aggregate = aggregate + nonces_a[i + block_index] + nonces_b[i + block_index];
        }
    }

    return aggregate; // Return the computed final aggregate
}

// Getters for Nonces
const std::vector<typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type> &Requestor::getNonceA() const
{
    return nonces_a;
}

const std::vector<typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type> &Requestor::getNonceB() const
{
    return nonces_b;
}

const typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Requestor::getAggregateBaseNonce() const
{
    // A & B nonce sum registers
    return generator * ( base_nonce * 2 * num_nodes * num_blocks_per_node );
}

const typename pallas::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type &Requestor::getGenerator() const
{
    return generator;
}

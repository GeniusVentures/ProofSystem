/**
 * @file       ElGamalKeyGenerator.hpp
 * @brief      El Gamal key generetor header file
 * @date       2024-01-17
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _EL_GAMAL_KEY_GENERATOR_HPP_
#define _EL_GAMAL_KEY_GENERATOR_HPP_
#include <memory>

#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/blueprint/r1cs/circuit.hpp>
#include "ElGamalTypes.hpp"

using namespace nil::crypto3;
class ElGamalKeyGenerator
{
public:
    ElGamalKeyGenerator( /* args */ );
    ~ElGamalKeyGenerator();

private:
    std::shared_ptr<elgamal::elgamal_keypair_type> key_pair;
    std::shared_ptr<elgamal::proof_keypair_type>   prover_key_pair;
    std::shared_ptr<nil::blueprint::blueprint<elgamal::field_type>> elgamal_bp;
    /* data */

  //      template<typename Scheme, typename Mode = pubkey::modes::isomorphic<Scheme>,
  //               typename ProcessingMode = typename Mode::encryption_policy, typename SinglePassRange,
  //               typename PubkeyAccumulator = pubkey::pubkey_accumulator_set<ProcessingMode>,
  //               typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<PubkeyAccumulator>,
  //               typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
  //      SchemeImpl encrypt(const SinglePassRange &range,
  //                         const pubkey::encryption_init_params_type<Scheme> &init_params) {
  //          return SchemeImpl(range, PubkeyAccumulator(init_params));

  //      }
   //              struct init_params_type {
   //                typename scalar_field_type::value_type r;
   //                const public_key_type &pubkey;
   //                const typename proof_system_type::keypair_type &gg_keypair;
   //                // TODO: accumulate primary_input and auxiliary_input
   //                const typename proof_system_type::primary_input_type &primary_input;
   //                const typename proof_system_type::auxiliary_input_type &auxiliary_input;
   //            };
};

ElGamalKeyGenerator::ElGamalKeyGenerator( /* args */ )
{
    static constexpr std::size_t                          tree_depth = 1;
    static constexpr std::size_t                          proof_idx  = 1;
    std::vector<std::array<bool, hash_component::digest_bits>> secret_keys;

    std::array<bool, hash_component::digest_bits> p;
    for ( size_t i = 0; i < hash_component::digest_bits; ++i )
    {
        p[i] = static_cast<bool>( std::rand() % 2 );
    }
    secret_keys.push_back( p );
    secret_keys.push_back( p );

    std::vector<bool> bool_vector_m = { 0, 1, 0, 0, 0, 0, 0 };
    const std::size_t eid_size      = 64;
    std::vector<bool> eid( eid_size );
    std::generate( eid.begin(), eid.end(), [&]() { return std::rand() % 2; } );
    std::vector<bool> eid_sk;
    std::copy( std::cbegin( eid ), std::cend( eid ), std::back_inserter( eid_sk ) );
    std::copy( std::cbegin( secret_keys[proof_idx] ), std::cend( secret_keys[proof_idx] ), std::back_inserter( eid_sk ) );

    std::vector<bool> sn = hash<test_policy::hash_type>( eid_sk );
    elgamal_bp = std::make_shared<nil::blueprint::blueprint<elgamal::field_type>>();
    components::block_variable<field_type>            m_block( elgamal_bp, bool_vector_m.size() );
    components::block_variable<field_type>            eid_block( elgamal_bp, eid.size() );
    components::digest_variable<field_type>           sn_digest( elgamal_bp, hash_component::digest_bits );
    components::digest_variable<field_type>           root_digest( elgamal_bp, merkle_hash_component::digest_bits );
    components::blueprint_variable_vector<field_type> address_bits_va;
    address_bits_va.allocate( elgamal_bp, tree_depth );
    merkle_proof_component                 path_var( elgamal_bp, tree_depth );
    components::block_variable<field_type> sk_block( elgamal_bp, secret_keys[proof_idx].size() );
    voting_component                       vote_var( elgamal_bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
                                                     components::blueprint_variable<field_type>( 0 ) );

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();

    //BOOST_CHECK( !bp.is_satisfied() );
    //path_var.generate_r1cs_witness( proof );
    //BOOST_CHECK(!bp.is_satisfied());
    address_bits_va.fill_with_bits_of_ulong( elgamal_bp, path_var.address );
    //BOOST_CHECK(!bp.is_satisfied());
    auto address = path_var.address;
    //BOOST_CHECK(address_bits_va.get_field_element_from_bits(bp) == path_var.address);
    m_block.generate_r1cs_witness( bool_vector_m );
    //BOOST_CHECK(!bp.is_satisfied());
    eid_block.generate_r1cs_witness( eid );
    //BOOST_CHECK(!bp.is_satisfied());
    sk_block.generate_r1cs_witness( secret_keys[proof_idx] );
    //BOOST_CHECK(!bp.is_satisfied());
    vote_var.generate_r1cs_witness( tree.root(), sn );
    //BOOST_CHECK(bp.is_satisfied());

    random_generator_type                d;
    std::vector<scalar_field_value_type> rnd;
    for ( std::size_t i = 0; i < m.size() * 3 + 2; ++i )
    {
        rnd.emplace_back( d() );
    }

    prover_key_pair = std::make_shared<proof_keypair_type>( generate<proof_system>( elgamal_bp.get_constraint_system() ) );

    std::make_shared<elgamal_keypair_type>(
        generate_keypair<encryption_scheme, modes::verifiable_encryption<encryption_scheme>>( rnd, { gg_keypair, m.size() } ); )
}

ElGamalKeyGenerator::~ElGamalKeyGenerator()
{
}

#endif

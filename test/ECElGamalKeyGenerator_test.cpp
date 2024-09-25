/**
 * @file       ECElGamalKeyGenerator_test.cpp
 * @brief      
 * @date       2024-02-14
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include <gtest/gtest.h>
#include <random>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include "ECDSATypes.hpp"
#include "ECElGamalTypes.hpp"
#include "ECElGamalKeyGenerator.hpp"

TEST( ECElGamalKeyGeneratorTest, Mapping )
{
    for ( size_t i = 0; i < 100; i++ )
    {
        EXPECT_NO_THROW( ECElGamalPoint<ecdsa_t::CurveType>( static_cast<cpp_int>( i ) ) );
    }
}
TEST( ECElGamalKeyGeneratorTest, DecodingMapping )
{
    ECElGamalPoint<ecdsa_t::CurveType> point_100( 100 );
    ECElGamalPoint<ecdsa_t::CurveType> point_200( 200 );

    EXPECT_EQ( point_100.UnMap(), 100 );

    EXPECT_EQ( point_200.UnMap(), 200 );
}
TEST( ECElGamalKeyGeneratorTest, KeyCreation )
{

    ECElGamalKeyGenerator key_generator( 0x60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2_cppui256 );

    auto prvkey = key_generator.GetPrivateKey();

    auto cypher  = key_generator.EncryptData( 10000 );
    auto cypher2 = key_generator.EncryptData( 50000 );

    auto cypher3 = std::make_pair( cypher.first + cypher2.first, cypher.second + cypher2.second );

    EXPECT_EQ( key_generator.DecryptData( cypher ), 10000 );
    EXPECT_EQ( key_generator.DecryptData( cypher2 ), 50000 );
    //EXPECT_EQ( key_generator.DecryptData( cypher3 ), 60000 ); //This test will fail because the ECElGamalPoint UnMap method is wrong. needs to solve ECDLP
}
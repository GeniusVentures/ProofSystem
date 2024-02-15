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
#include "ECElGamalKeyGenerator.hpp"

TEST( ECElGamalKeyGeneratorTest, Mapping )
{
    for ( size_t i = 0; i < 100; i++ )
    {
        EXPECT_NO_THROW( ECElGamalKeyGenerator::ECElGamalPoint<ecdsa_t::CurveType>( static_cast<cpp_int>( i ) ) );
    }
}
TEST( ECElGamalKeyGeneratorTest, DecodingMapping )
{
    ECElGamalKeyGenerator::ECElGamalPoint<ecdsa_t::CurveType> point_100( 100 );
    ECElGamalKeyGenerator::ECElGamalPoint<ecdsa_t::CurveType> point_200( 200 );

    EXPECT_EQ( point_100.UnMap(), 100 );

    EXPECT_EQ( point_200.UnMap(), 200 );
}
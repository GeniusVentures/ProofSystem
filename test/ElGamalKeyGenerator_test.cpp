/**
 * @file       ElGamalKeyGenerator_test.cpp
 * @brief      Module to test El Gamal Key Generation module 
 * @date       2024-01-29
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#include <gtest/gtest.h>
#include "ElGamalKeyGenerator.hpp"

TEST( ElGamalKeyGeneratorTest, Initialization )
{
    // Created 'n' instances of generator and check for exception
    // Each generation can take some ms
    for ( size_t i = 0; i < 10; i++ )
    {
        try
        {
            ElGamalKeyGenerator{};
        }
        catch ( ... )
        {
            FAIL() << "ElGamalKeyGenerator not created";
            break;
        }
    }
}
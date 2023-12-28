#include <gtest/gtest.h>
#include "PallasMapper.hpp"

TEST( PallasMapperTest, PallasZeroMap )
{
    PallasMapper mapper;

    EXPECT_TRUE(mapper==0);
    mapper+=10;
    mapper+=10;
    EXPECT_TRUE(mapper==20);
    EXPECT_FALSE(mapper==30);
    mapper-=10;
    EXPECT_TRUE(mapper==10);
}

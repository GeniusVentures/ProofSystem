#include "nil/crypto3/random/algebraic_random_device.hpp"
#include "nil/crypto3/algebra/curves/pallas.hpp"
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;
class PallasMapper
{
    using CurveType      = nil::crypto3::algebra::curves::pallas;
    using generator_type = nil::crypto3::random::algebraic_random_device<CurveType::scalar_field_type>;

    
private:
    /* data */
    curves::pallas::g1_type<>::value_type zero_g1_value;
    curves::pallas::g1_type<>::value_type curr_value;


public:
    PallasMapper( /* args */ );
    PallasMapper(curves::pallas::scalar_field_type::value_type random_val);
    ~PallasMapper();
    static generator_type random_gen;
    PallasMapper& operator+=(const std::int32_t value)
    {
        auto val_multi = static_cast<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<>>>(value);
        curves::pallas::g1_type<>::value_type g1_value = val_multi*curves::pallas::g1_type<>::value_type().one();
        curr_value+=g1_value;
        return *this;
    }
    PallasMapper& operator-=(const std::int32_t value)
    {
        auto val_multi = static_cast<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<>>>(value);
        curves::pallas::g1_type<>::value_type g1_value = val_multi*curves::pallas::g1_type<>::value_type().one();
        curr_value-=g1_value;
        return *this;
    }

    bool operator==(const std::int32_t value)
    {
        auto val_multi = static_cast<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<>>>(value);
        curves::pallas::g1_type<>::value_type g1_value = val_multi*curves::pallas::g1_type<>::value_type().one();

        return curr_value==g1_value; 
    }
};

PallasMapper::generator_type PallasMapper::random_gen;

PallasMapper::PallasMapper( /* args */ )
{
    curves::pallas::scalar_field_type::value_type random_scalar_value = random_gen();
    zero_g1_value = random_scalar_value*curves::pallas::g1_type<>::value_type().one() - random_scalar_value*curves::pallas::g1_type<>::value_type().one();
    curr_value = zero_g1_value;

}
PallasMapper::PallasMapper(curves::pallas::scalar_field_type::value_type random_val )
{
    zero_g1_value = random_val*curves::pallas::g1_type<>::value_type().one() - random_val*curves::pallas::g1_type<>::value_type().one();
    curr_value = zero_g1_value;
}

PallasMapper::~PallasMapper()
{
}


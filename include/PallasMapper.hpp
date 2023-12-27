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
    static generator_type random_gen;

public:
    PallasMapper( /* args */ );
    ~PallasMapper();
};

PallasMapper::generator_type PallasMapper::random_gen;

PallasMapper::PallasMapper( /* args */ )
{
    curves::pallas::scalar_field_type::value_type random_scalar_value = random_gen();

    //curves::pallas::g1_type<>::value_type random_g1_value = random_element<typename CurveType::template g1_type<>>();
    curves::pallas::g1_type<>::value_type random_g1_value = random_scalar_value*curves::pallas::g1_type<>::value_type().one();
    curves::pallas::g1_type<>::value_type zero_g1_value;


    std::cout << "zero_g1_value.to_affine().X.data:  " << zero_g1_value.to_affine().X.data << std::endl;
    std::cout << "zero_g1_value.X.data " << zero_g1_value.X.data << std::endl;
    std::cout << "zero_g1_value.is_well_formed() " << zero_g1_value.is_well_formed() << std::endl;
    std::cout << "random_g1_value.to_affine().X.data " << random_g1_value.to_affine().X.data << std::endl;
    std::cout << "random_g1_value.to_affine().X.data " << random_g1_value.X.data << std::endl;
    std::cout << "random_g1_value.is_well_formed() " << random_g1_value.is_well_formed() << std::endl;

}

PallasMapper::~PallasMapper()
{
}


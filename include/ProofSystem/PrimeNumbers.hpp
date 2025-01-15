/**
 * @file       PrimeNumbers.hpp
 * @brief      Handles prime number generation/checking
 * @date       2024-01-26
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _PRIME_NUMBERS_HPP_
#define _PRIME_NUMBERS_HPP_

#define _USE_CRYPTO3_

#include <ctime>
#include <unordered_map>

#ifdef _USE_CRYPTO3_
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/miller_rabin.hpp>
#else
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#endif

class PrimeNumbers
{
public:
#ifdef _USE_CRYPTO3_
    using cpp_int = nil::crypto3::multiprecision::cpp_int;
#else
    using cpp_int = boost::multiprecision::cpp_int;
#endif

    template <std::size_t bit_size>
    static bool GenerateSafePrime( std::size_t max_attempts, cpp_int &out_val )
    {
        std::size_t loop_limit = max_attempts * 50000;
        auto        seed       = clock();

        boost::mt11213b base_gen( seed );

        boost::random::independent_bits_engine<boost::mt11213b, bit_size, cpp_int> engine( base_gen );

        boost::mt19937 ref_engine( seed );

        for ( std::size_t i = 0; i < loop_limit; ++i )
        {
            cpp_int candidate = engine();

            if ( miller_rabin_test( candidate, max_attempts, ref_engine ) && //
                 miller_rabin_test( ( candidate - 1 ) / 2, max_attempts, ref_engine ) )
            {
                out_val = std::move( candidate );
                return true;
            }
        }

        return false;
    }

    // In the range [2, prime_number)
    static cpp_int GetRandomNumber( const cpp_int &prime_number );

    // Finds a generator for the multiplicative group modulo prime_number
    static bool GetGeneratorFromPrime( std::size_t max_attempts, cpp_int prime_number, cpp_int &out_val );

    static cpp_int ModInverseEuclideanDivision( cpp_int x, cpp_int prime );

    static cpp_int SqrtMod( const cpp_int &number, const cpp_int &prime );

    static cpp_int PowHighPrec( const cpp_int &value, const int64_t &exp );

    class BabyStepGiantStep
    {
    public:
        BabyStepGiantStep( const cpp_int &prime, const cpp_int &generator );

        cpp_int SolveECDLP( const cpp_int &number );

    private:
        cpp_int                              g_n_inv;
        cpp_int                              step_size;
        cpp_int                              prime_number;
        std::unordered_map<cpp_int, cpp_int> value_table;
    };
};

#endif

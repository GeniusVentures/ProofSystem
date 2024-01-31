/**
 * @file       PrimeNumbers.hpp
 * @brief      Handles prime number generation/checking
 * @date       2024-01-26
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _PRIME_NUMBERS_HPP_
#define _PRIME_NUMBERS_HPP_

#define _USE_CRYPTO3_

#include <boost/multiprecision/random.hpp>
#include <time.h>
#ifdef _USE_CRYPTO3_
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/miller_rabin.hpp>
using namespace nil::crypto3::multiprecision;
#else
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/multiprecision/cpp_int.hpp>
using namespace boost::multiprecision;
#endif

using namespace boost::random;

typedef cpp_int mp_int;

class PrimeNumbers
{

public:
    template <std::size_t bit_size>
    static bool GenerateSafePrime( std::size_t max_attempts, cpp_int &out_val )
    {
        bool        ret         = false;
        cpp_int     retval      = 0;
        std::size_t loop_limit  = max_attempts * 50000;
        std::size_t num_attemps = 0;

        boost::mt11213b base_gen( clock() );

        independent_bits_engine<boost::mt11213b, bit_size, cpp_int> engine( base_gen );

        boost::mt19937 ref_engine( clock() );
        do
        {
            retval = engine();
            if ( !miller_rabin_test( retval, max_attempts, ref_engine ) )
            {
                num_attemps++;
                continue;
            }
            // Value n is probably prime, see if (n-1)/2 is also prime:
            if ( !miller_rabin_test( ( retval - 1 ) / 2, max_attempts, ref_engine ) )
            {
                num_attemps++;
                continue;
            }
            out_val = retval;
            ret     = true;
            break;

        } while ( --loop_limit );

        return ret;
    }

    static cpp_int GetRandomNumber( cpp_int prime_number )
    {
        boost::mt19937 ref_engine( clock() );

        boost::random::uniform_int_distribution<cpp_int> dist( 2, prime_number - 1 );
        return dist( ref_engine );
    }

    static bool GetGeneratorFromPrime( std::size_t max_attempts, cpp_int prime_number, cpp_int &out_val )
    {
        bool    ret       = false;
        cpp_int order     = ( prime_number - 1 ) / 2;
        cpp_int generator = 0;

        do
        {
            generator = PrimeNumbers::GetRandomNumber( prime_number );
            if ( boost::math::gcd( generator, order ) != 1 )
            {
                continue;
            }

            if ( powm( generator, order, prime_number ) != 1 )
            {
                continue;
            }
            out_val = generator;
            ret     = true;
            break;

        } while ( --max_attempts );

        return ret;
    }

    static cpp_int ModInverseEuclideanDivision( cpp_int x, cpp_int prime )
    {
        cpp_int original_prime = prime;
        cpp_int r              = 0;
        cpp_int r_new          = 1;
        cpp_int t              = 1;
        cpp_int t_new          = 0;
        cpp_int quotient;
        cpp_int remainder;
        cpp_int temp;

        if ( gcd( x, prime ) != 1 )
        {
            throw std::runtime_error( "x and prime are not co-primes" );
        }
        while ( x != 0 )
        {
            quotient  = prime / x;
            remainder = prime % x;

            temp  = r - quotient * r_new;
            r     = r_new;
            r_new = temp;

            temp  = t - quotient * t_new;
            t     = t_new;
            t_new = temp;

            prime = x;
            x     = remainder;
        }
        if ( r < 0 )
        {
            r += original_prime;
        }

        return r;
    }
};

#endif

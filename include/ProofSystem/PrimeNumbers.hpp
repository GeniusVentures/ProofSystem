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
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
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
        bool        ret         = false;
        cpp_int     retval      = 0;
        std::size_t loop_limit  = max_attempts * 50000;
        std::size_t num_attemps = 0;

        boost::mt11213b base_gen( clock() );

        boost::random::independent_bits_engine<boost::mt11213b, bit_size, cpp_int> engine( base_gen );

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
        boost::random::mt19937 ref_engine( clock() );

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

    static cpp_int SqrtMod( const cpp_int &number, const cpp_int &prime )
    {

        cpp_int ret = -1;
        do
        {
            if ( powm( number, ( prime - 1 ) / 2, prime ) != 1 )
            {
                // No solution exists
                break;
            }
            if ( prime % 4 == 3 )
            {
                ret = powm( number, ( prime + 1 ) / 4, prime );
                break;
            }
            cpp_int q = prime - 1;
            cpp_int s = 0;
            while ( q % 2 == 0 )
            {
                s += 1;
                q /= 2;
            }
            cpp_int z = 2;
            while ( powm( z, ( prime - 1 ) / 2, prime ) != prime - 1 )
            {
                z++;
            }
            // Find the first quadratic non-residue z by brute-force search

            cpp_int c = powm( z, q, prime );
            ret       = powm( number, ( q + 1 ) / 2, prime );
            cpp_int t = powm( number, q, prime );
            cpp_int m = s;

            while ( t != 1 )
            {
                cpp_int i = 0, temp = t;
                while ( temp != 1 && i < ( m - 1 ) )
                {
                    temp = powm( temp, 2, prime );
                    i++;
                }

                cpp_int b = powm( c, cpp_int( 1 << static_cast<unsigned long long>( m - i - 1 ) ), prime );
                ret       = ( ret * b ) % prime;
                t         = ( t * b * b ) % prime;
                c         = ( b * b ) % prime;
                m         = i;
            }
        } while ( 0 );

        return ret;
    }
    static cpp_int PowHighPrec( const cpp_int &value, const long &exp )
    {
        cpp_int retval = 1;
        for ( std::size_t i = 0; i < exp; ++i )
        {
            retval *= value;
        }
        return retval;
    }

    struct BabyStepGiantStep
    {
        BabyStepGiantStep( cpp_int prime, cpp_int generator ) : prime_number( prime )
        {
            step_size = static_cast<cpp_int>( pow( 2, 16 ) + 1 );
            for ( cpp_int i = 0; i < step_size; ++i )
            {
                cpp_int value      = powm( generator, i, prime_number );
                value_table[value] = i;
            }

            g_n_inv = powm( generator, step_size * ( prime - 2 ), prime_number );
        }

        cpp_int SolveECDLP( const cpp_int &number )
        {
            for ( cpp_int i = 0, cur = number % prime_number; i <= step_size; ++i )
            {
                if ( value_table.find( cur ) != value_table.end() )
                {
                    return i * step_size + value_table[cur];
                }
                cur = ( cur * g_n_inv ) % prime_number;
            }
            // If no solution was found
            throw std::runtime_error( "No ECDLP solution found" );
        }

    private:
        cpp_int                              g_n_inv;
        cpp_int                              step_size;
        cpp_int                              prime_number;
        std::unordered_map<cpp_int, cpp_int> value_table;
    };
};

#endif

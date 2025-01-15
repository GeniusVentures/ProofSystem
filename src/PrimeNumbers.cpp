#include <ProofSystem/PrimeNumbers.hpp>

#include <random>

bool PrimeNumbers::GetGeneratorFromPrime( std::size_t max_attempts, cpp_int prime_number, cpp_int &out_val )
{
    cpp_int order = ( prime_number - 1 ) / 2;

    for ( std::size_t i = 0; i < max_attempts; ++i )
    {
        cpp_int generator = PrimeNumbers::GetRandomNumber( prime_number );

        if ( boost::math::gcd( generator, order ) == 1 && //
             powm( generator, order, prime_number ) == 1 )
        {
            out_val = generator;
            return true;
        }
    }

    return false;
}

PrimeNumbers::cpp_int PrimeNumbers::GetRandomNumber( const PrimeNumbers::cpp_int &prime_number )
{
    std::random_device                               rd;
    std::mt19937                                     engine( rd() ); // Seed with hardware entropy
    boost::random::uniform_int_distribution<cpp_int> dist( 2, prime_number - 1 );
    return dist( engine );
}

PrimeNumbers::cpp_int PrimeNumbers::ModInverseEuclideanDivision( cpp_int x, cpp_int prime )
{
    cpp_int original_prime = prime;
    cpp_int r              = 0;
    cpp_int r_new          = 1;

    if ( gcd( x, prime ) != 1 )
    {
        throw std::runtime_error( "x and prime are not co-primes" );
    }

    while ( x != 0 )
    {
        cpp_int quotient  = prime / x;
        cpp_int remainder = prime % x;

        std::swap( r, r_new );
        r_new -= quotient * r;

        prime = x;
        x     = remainder;
    }

    if ( r < 0 )
    {
        r += original_prime;
    }

    return r;
}

PrimeNumbers::cpp_int PrimeNumbers::SqrtMod( const PrimeNumbers::cpp_int &number, const PrimeNumbers::cpp_int &prime )
{

    if ( powm( number, ( prime - 1 ) / 2, prime ) != 1 )
    {
        // No solution exists
        return -1;
    }

    // Special case: prime ≡ 3 (mod 4)
    if ( prime % 4 == 3 )
    {
        return powm( number, ( prime + 1 ) / 4, prime );
    }

    // Tonelli-Shanks algorithm for general primes
    PrimeNumbers::cpp_int q = prime - 1;
    PrimeNumbers::cpp_int s = 0;
    while ( q % 2 == 0 )
    {
        s += 1;
        q /= 2;
    }

    PrimeNumbers::cpp_int z = 2;
    while ( powm( z, ( prime - 1 ) / 2, prime ) == 1 )
    {
        z++;
    }

    // Find the first quadratic non-residue z by brute-force search
    PrimeNumbers::cpp_int c = powm( z, q, prime );
    PrimeNumbers::cpp_int r = powm( number, ( q + 1 ) / 2, prime );
    PrimeNumbers::cpp_int t = powm( number, q, prime );
    PrimeNumbers::cpp_int m = s;

    while ( t != 1 )
    {
        PrimeNumbers::cpp_int i    = 0;
        PrimeNumbers::cpp_int temp = t;
        while ( temp != 1 && i < m )
        {
            temp = powm( temp, 2, prime );
            i++;
        }

        PrimeNumbers::cpp_int b = powm( c, PrimeNumbers::cpp_int( 1 << static_cast<uint64_t>( m - i - 1 ) ), prime );
        r                       = ( r * b ) % prime;
        t                       = ( t * b * b ) % prime;
        c                       = ( b * b ) % prime;
        m                       = i;
    }

    return r;
}

PrimeNumbers::cpp_int PrimeNumbers::PowHighPrec( const PrimeNumbers::cpp_int &value, const int64_t &exp )
{
    PrimeNumbers::cpp_int retval = 1;
    for ( auto i = 0; i < exp; ++i )
    {
        retval *= value;
    }
    return retval;
}

PrimeNumbers::BabyStepGiantStep::BabyStepGiantStep( const PrimeNumbers::cpp_int &prime, const PrimeNumbers::cpp_int &generator ) :
    prime_number( prime )
{
    step_size = static_cast<PrimeNumbers::cpp_int>( pow( 2, 16 ) + 1 );
    for ( PrimeNumbers::cpp_int i = 0; i < step_size; ++i )
    {
        PrimeNumbers::cpp_int value = powm( generator, i, prime_number );
        value_table[value]          = i;
    }

    g_n_inv = powm( generator, step_size * ( prime - 2 ), prime_number );
}

PrimeNumbers::cpp_int PrimeNumbers::BabyStepGiantStep::SolveECDLP( const PrimeNumbers::cpp_int &number )
{
    for ( PrimeNumbers::cpp_int i = 0, cur = number % prime_number; i <= step_size; ++i )
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

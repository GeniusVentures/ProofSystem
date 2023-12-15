//
// Created by Super Genius on 12/6/23.
//

#ifndef PROOFSYSTEM_UTIL_HPP
#define PROOFSYSTEM_UTIL_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <type_traits>

namespace util
{

    /**
     * Convert a byte array to a hexadecimal string.
     * @param bytes A vector of bytes to be converted.
     * @return A hexadecimal string representation of the bytes.
     */
    std::string to_string( const std::vector<unsigned char> &bytes );

    // Additional utility functions can be declared here.

    static bool isLittleEndian()
    {
        std::uint32_t num     = 1;
        std::uint8_t *bytePtr = reinterpret_cast<std::uint8_t *>( &num );

        return ( *bytePtr == 1 );
    }

    static std::int32_t HexASCII2Num( char *p_char, std::size_t num_nibbles_resolution )
    {
        std::int32_t sum = 0;

        for ( std::int32_t i = 0; i < num_nibbles_resolution; ++i )
        {
            if ( std::isdigit( p_char[i] ) )
            {

                sum += ( ( p_char[i] - '0' ) << ( 4 * ( num_nibbles_resolution - i - 1 ) ) );
            }
            else
            {
                sum += ( ( std::toupper( p_char[i] ) - 'A' + 10 ) << ( 4 * ( num_nibbles_resolution - i - 1 ) ) );
            }
        }

        return sum;
    }
    static std::vector<std::uint8_t> HexASCII2NumStr( char *p_char, std::size_t char_ptr_size, std::size_t num_nibbles_resolution )
    {
        std::vector<std::uint8_t> out_vect;

        for ( std::size_t i = 0; i < char_ptr_size; i += num_nibbles_resolution )
        {
            out_vect.insert( out_vect.begin(), static_cast<std::uint8_t>( HexASCII2Num( &p_char[i], num_nibbles_resolution ) ) );
        }
        return out_vect;
    }
    template <typename T, std::size_t N = std::extent_v<T>>
    void AdjustEndianess( T &data )
    {
        static_assert( std::is_same_v<T, std::vector<uint8_t>> || std::is_same_v<T, std::array<uint8_t, N>> );
        if ( !isLittleEndian() )
        {
            std::reverse( data.begin(), data.end() );
        }
    }

}

#endif //PROOFSYSTEM_UTIL_HPP

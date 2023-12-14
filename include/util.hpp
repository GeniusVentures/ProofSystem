//
// Created by Super Genius on 12/6/23.
//

#ifndef PROOFSYSTEM_UTIL_HPP
#define PROOFSYSTEM_UTIL_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

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

        for ( std::int32_t i = num_nibbles_resolution - 1; i >= 0; --i )
        {
            if ( std::isdigit( p_char[i] ) )
            {
                sum += ( *p_char - '0' ) << ( 8 * i );
            }
            else
            {
                sum += ( std::toupper( *p_char ) - 'A' + 10 ) << ( 8 * i );
            }
        }

        return sum;
    }
    static std::vector<std::uint32_t> HexASCII2Num( char *p_char, std::size_t char_ptr_size, std::size_t num_nibbles_resolution )
    {
        std::vector<std::uint32_t> out_vect;

        for ( std::size_t i = 0; i < char_ptr_size; i += num_nibbles_resolution )
        {
            out_vect.push_back( HexASCII2Num( &p_char[i], num_nibbles_resolution ) );
        }
        return out_vect;
    }

}

#endif //PROOFSYSTEM_UTIL_HPP

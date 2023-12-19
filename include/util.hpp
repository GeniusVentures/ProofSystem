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
#include <optional>

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

    template <typename T>
    static T HexASCII2Num( const char *p_char, std::size_t num_nibbles_resolution = sizeof( T ) * 2 )
    {
        T sum = 0;

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
    template <typename T>
    static std::vector<T> HexASCII2NumStr( const char *p_char, std::size_t char_ptr_size )
    {
        static_assert( std::is_same_v<T, uint8_t> || std::is_same_v<T, uint16_t> || std::is_same_v<T, uint32_t> );
        std::vector<T> out_vect;
        std::size_t    num_nibbles_resolution = ( sizeof( T ) * 2 );
        auto           point_of_insertion     = [&]()
        {
            if ( isLittleEndian() )
            {
                return out_vect.begin();
            }
            else
            {
                return out_vect.end();
            }
        };

        for ( std::size_t i = 0; i < char_ptr_size; i += num_nibbles_resolution )
        {
            out_vect.insert( point_of_insertion(), static_cast<T>( HexASCII2Num<T>( &p_char[i] ) ) );
        }
        return out_vect;
    }
    template <typename T, std::size_t N = std::extent_v<T>>
    void AdjustEndianess( T &data, std::optional<typename T::iterator> start = std::nullopt,
                          std::optional<typename T::iterator> finish = std::nullopt )
    {
        static_assert( std::is_same_v<T, std::vector<uint8_t>> || std::is_same_v<T, std::array<uint8_t, N>> );
        if ( !start )
        {
            start = data.begin();
        }
        if ( !finish )
        {
            finish = data.end();
        }
        if ( !isLittleEndian() )
        {
            std::reverse( start.value(), finish.value() );
        }
    }

}

#endif //PROOFSYSTEM_UTIL_HPP

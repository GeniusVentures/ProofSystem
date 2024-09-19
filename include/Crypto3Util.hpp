/**
 * @file       Crypto3Util.hpp
 * @brief      Crypto3 utilities module
 * @date       2024-01-30
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _CRYPTO3_UTIL_HPP_
#define _CRYPTO3_UTIL_HPP_
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_int/serialize.hpp>

using namespace nil::crypto3::multiprecision;
struct Crypto3Util
{

    static cpp_int BytesToCppInt( std::vector<std::uint8_t> &bytes )
    {
        cpp_int retval;
        for ( uint8_t byte : bytes )
        {
            retval = ( retval << 8 ) | byte;
        }

        return retval;
    }
    static std::vector<std::uint8_t> CppIntToBytes( cpp_int &big_num )
    {
        std::vector<uint8_t> bytes;
        cpp_int remaining = big_num;
        while ( remaining != 0 )
        {
            bytes.insert(bytes.begin(), static_cast<uint8_t>( remaining & 0xFF ) );
            remaining >>= 8;
        }
        return bytes;
    }
}

#endif

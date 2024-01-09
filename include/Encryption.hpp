/**
 * @file       Encryption.hpp
 * @brief      Interface class for encryption 
 * @date       2024-01-05
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef _ENCRYPTION_HPP_
#define _ENCRYPTION_HPP_

#include <vector>

class Encryption
{
private:
public:
    virtual std::vector<std::uint8_t> EncryptData(std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data) = 0;
    virtual std::vector<std::uint8_t> DecryptData(std::vector<std::uint8_t> data, std::vector<std::uint8_t> key_data) = 0;
};

#endif

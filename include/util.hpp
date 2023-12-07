//
// Created by Super Genius on 12/6/23.
//

#ifndef PROOFSYSTEM_UTIL_HPP
#define PROOFSYSTEM_UTIL_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

namespace util {

    /**
     * Convert a byte array to a hexadecimal string.
     * @param bytes A vector of bytes to be converted.
     * @return A hexadecimal string representation of the bytes.
     */
    std::string to_string(const std::vector<unsigned char>& bytes);

    // Additional utility functions can be declared here.

}

#endif //PROOFSYSTEM_UTIL_HPP

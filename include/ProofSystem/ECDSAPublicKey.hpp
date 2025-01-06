/**
 * @file       ECDSAPublicKey.hpp
 * @brief      ECDSA public key base class
 * @date       2023-12-26
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#include <string>
#include <vector>
#include "ProofSystem/util.hpp"

#ifndef _ECDSA_PUBLIC_KEY_HPP_
#define _ECDSA_PUBLIC_KEY_HPP_
/**
 * @brief       Base class to organize public key values of ECDSA
 */
class ECDSAPublicKey
{
public:
    /**
     * @brief       Constructs a new ECDSAPublicKey object
     * @param[in]   X_data vector representing the X coordinate of the public key. 
     * @param[in]   Y_data vector representing the Y coordinate of the public key.
     */
    explicit ECDSAPublicKey( const std::vector<std::uint8_t> &X_data, const std::vector<std::uint8_t> &Y_data ) :
        X( util::to_string( X_data ) ), //
        Y( util::to_string( Y_data ) ), //
        X_vect( X_data ),               //
        Y_vect( Y_data )                //
    {
    }
    /**
     * @brief       Virtual destructor to prevent memory leak
     */
    virtual ~ECDSAPublicKey()
    {
    }

    const std::string               X;      ///< String representation of X coordinate
    const std::string               Y;      ///< String representation of Y coordinate
    const std::vector<std::uint8_t> X_vect; ///< Vector representation of X coordinate
    const std::vector<std::uint8_t> Y_vect; ///< Vector representation of Y coordinate

    /**
     * @brief       Overloads the assignment to string. 
     * @return      The appropriate public key value used for the parent class
     */
    operator std::string &()
    {
        if ( pubkey_used_value == "" )
        {
            pubkey_used_value = CalcPubkeyUsedValue();
        }
        return pubkey_used_value;
    }

    std::string GetEntireKey()
    {
        return (X + Y);
    }

private:
    std::string pubkey_used_value = ""; ///< Used value of the public key (compressed, uncompressed..)

    /**
     * @brief       Calculates the single data used key value
     * @return      Public key mashed value
     */
    virtual std::string CalcPubkeyUsedValue() const = 0;
};

#endif

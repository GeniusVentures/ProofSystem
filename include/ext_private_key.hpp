/**
 * @file       ext_private_key.hpp
 * @brief      Extented private key class header file
 * @date       2023-12-16
 * @author     Super Genius (ken@gnus.ai)
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */

#ifndef PROOFSYSTEM_EXT_PRIVATE_KEY_HPP
#define PROOFSYSTEM_EXT_PRIVATE_KEY_HPP

#include "nil/crypto3/pubkey/ecdsa.hpp"
#include "nil/crypto3/pkpad/emsa/emsa1.hpp"
#include "nil/crypto3/algebra/curves/secp_k1.hpp"
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::pubkey;

namespace nil
{
    namespace crypto3
    {
        namespace pubkey
        {
            /**
             * @brief       Forward declaration of class
             */
            template <typename Scheme, typename = void>
            struct ext_private_key;

            /**
             * @brief       Extended private key class with deterministic generator and operator modifications
             */
            template <typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct ext_private_key<
                ecdsa<CurveType, Padding, GeneratorType, DistributionType>,
                typename std::enable_if<std::is_same<
                    GeneratorType, random::rfc6979<typename CurveType::scalar_field_type::value_type,
                                                   typename ecdsa<CurveType, Padding, GeneratorType, DistributionType>::hash_type>>::value>::type> :
                public private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>
            {
                using private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>::private_key;


                /**
                 * @brief       Multiplication overload to derive public key from private key multiplication
                 * @param[in]   lhs: public key to be multiplied by own private key data
                 * @return      New public key
                 */
                const public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> 
                operator*(const public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> &lhs ) const 
                {
                    return lhs.pubkey_data() * this->privkey;
                }
            };
        }
    }
}
#endif //PROOFSYSTEM_EXT_PRIVATE_KEY_HPP

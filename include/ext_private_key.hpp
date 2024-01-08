//
// Created by Super Genius on 12/16/23.
//

#ifndef PROOFSYSTEM_EXT_PRIVATE_KEY_HPP
#define PROOFSYSTEM_EXT_PRIVATE_KEY_HPP

#include "nil/crypto3/pubkey/ecdsa.hpp"
#include "nil/crypto3/pkpad/emsa/emsa1.hpp"
#include "nil/crypto3/algebra/curves/secp_k1.hpp"
#include <nil/crypto3/algebra/marshalling.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::pubkey;

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            template<typename Scheme, typename = void>
            struct ext_private_key;

            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct ext_private_key<
                    ecdsa<CurveType, Padding, GeneratorType, DistributionType>,
                    typename std::enable_if<!std::is_same<
                            GeneratorType,
                            random::rfc6979<typename CurveType::scalar_field_type::value_type,
                                    typename ecdsa<CurveType, Padding, GeneratorType, DistributionType>::hash_type>>::
                    value>::type>
                    : public private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> {

                // Constructor with additional arguments or customization
                ext_private_key(const typename private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>::private_key_type &key)
                        : private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>(key) {
                    std::vector<std::uint8_t> rand_priv_output(32);
                    ::nil::marshalling::bincode::field<bitcoin::scalar_field_type>::field_element_to_bytes<std::vector<std::uint8_t>::iterator>(
                            key.data, rand_priv_output.begin(), rand_priv_output.end() );

                    std::cout << "random number input: ";
                    for (uint i=0; i< rand_priv_output.size(); i++) {
                        std::cout << std::hex << unsigned(rand_priv_output[i]);
                    }
                    std::cout << std::endl;
                }

                inline typename private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>::private_key_type getPrivKey() const {
                    return private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>::privkey.data;
                }
            };
        }
    }
}
#endif //PROOFSYSTEM_EXT_PRIVATE_KEY_HPP

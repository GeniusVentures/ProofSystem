/**
 * @file       ECElGamalKeyGenerator.hpp
 * @brief      Header file of EC ElGamal module
 * @date       2024-02-01
 * @author     Henrique A. Klein (henryaklein@gmail.com)
 */
#ifndef _EC_ELGAMAL_HPP_
#define _EC_ELGAMAL_HPP_

#include "ECElGamalTypes.hpp"
#include "ECDSATypes.hpp"

class ECElGamalKeyGenerator
{

#ifdef _USE_CRYPTO3_
    using cpp_int = nil::crypto3::multiprecision::cpp_int;
#else
    using cpp_int = boost::multiprecision::cpp_int;
#endif

public:
    ECElGamalKeyGenerator( const cpp_int &key_scalar )
    {
        private_key = std::make_shared<PrivateKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>>(
            static_cast<typename PrivateKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>::private_key_type>( key_scalar ) );
        public_key = std::make_shared<PublicKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>>( *private_key );
    }

    const PrivateKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type> &GetPrivateKey() const
    {
        return *private_key;
    }

    std::pair<ECElGamalPoint<ecdsa_t::CurveType>, ECElGamalPoint<ecdsa_t::CurveType>> EncryptData( const cpp_int &data )
    {
        ecdsa_t::random_generator_type     random_gen;
        auto                               random_num = random_gen();
        ECElGamalPoint<ecdsa_t::CurveType> C1( random_num * ECElGamalPoint<ecdsa_t::CurveType>::curve_point_type::one() );

        ECElGamalPoint<ecdsa_t::CurveType> M( data );
        ECElGamalPoint<ecdsa_t::CurveType> kQ( random_num * public_key->pubkey_data() );
        ECElGamalPoint<ecdsa_t::CurveType> C2 = M + kQ;

        return std::make_pair( C1, C2 );
    }
    cpp_int DecryptData( const std::pair<ECElGamalPoint<ecdsa_t::CurveType>, ECElGamalPoint<ecdsa_t::CurveType>> &data )
    {

        ECElGamalPoint<ecdsa_t::CurveType> dC1( ( *data.first.curve_point ) * private_key->GetPrivateKeyScalar() );
        ECElGamalPoint<ecdsa_t::CurveType> M = data.second - dC1;

        return M.UnMap();
    }

private:
    std::shared_ptr<PrivateKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>> private_key; ///< Private key instance
    std::shared_ptr<PublicKey<ecdsa_t::CurveType, ecdsa_t::padding_policy, ecdsa_t::generator_type>>  public_key;  ///< Public key instance
};

#endif

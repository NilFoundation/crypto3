//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECDH_KEY_HPP
#define CRYPTO3_PUBKEY_ECDH_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType>
            struct ecdh_public_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;

                constexpr static const std::size_t key_bits = curve_type::modulus_bits;
                typedef typename curve_type::modulus_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::modulus_bits;
                typedef typename curve_type::modulus_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
            };

            template<typename CurveType>
            struct ecdh_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;

                constexpr static const std::size_t key_bits = curve_type::modulus_bits;
                typedef typename curve_type::modulus_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::modulus_bits;
                typedef typename curve_type::modulus_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool agree(const signature_type &val, const key_schedule_type &key) {
                    pk_operations::key_agreement_with_kdf(kdf), m_group(key.domain()),
                        m_rng(rng) m_l_times_priv =
                            inverse_mod(m_group.get_cofactor(), m_group.get_order()) * key.private_value();
                    //---------------
                    const ec_group m_group;
                    boost::multiprecision::number<Backend, ExpressionTemplates> m_l_times_priv;
                    random_number_generator &m_rng;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;
                    //--------------

                    point_gfp input_point = m_group.get_cofactor() * m_group.os2ecp(w, w_len);
                    input_point.randomize_repr(m_rng);

                    const point_gfp S = m_group.blinded_var_point_multiply(input_point, m_l_times_priv, m_rng, m_ws);

                    if (!S.on_the_curve()) {
                        throw internal_error("ECDH agreed value was not on the curve");
                    }
                    return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_1363(
                        S.get_affine_x(), m_group.get_p_bytes());
                }
            };

            template<typename CurveType>
            struct ecdh {
                typedef CurveType curve_type;

                typedef ecdh_public_key<CurveType> public_key_type;
                typedef ecdh_private_key<CurveType> private_key_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECGDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECGDSA_KEY_HPP

#include <nil/crypto3/pubkey/ecc_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme, typename Hash>
                struct emsa1;
            }

            template<typename CurveType>
            struct ecgdsa_public_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool verify(const signature_type &val, const key_schedule_type &key) {
                    pk_operations::verification_with_emsa(emsa), m_group(ecgdsa.domain()),
                        m_public_point(ecgdsa.public_point())

                        //----------------------------
                    const ec_group m_group;
                    const point_gfp &m_public_point;

                    //---------------------------

                    if (sig_len != m_group.get_order_bytes() * 2) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> e(msg, msg_len,
                        m_group.get_order_bits());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> r(sig, sig_len / 2);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> s(sig + sig_len / 2, sig_len / 2);

                    if (r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order()) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> w =
                        inverse_mod(r, m_group.get_order());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> u1 =
                        m_group.multiply_mod_order(e, w);
                    const boost::multiprecision::number<Backend, ExpressionTemplates> u2 =
                        m_group.multiply_mod_order(s, w);
                    const point_gfp R = m_group.point_multiply(u1, m_public_point, u2);

                    if (R.is_zero()) {
                        return false;
                    }

                    const boost::multiprecision::number<Backend, ExpressionTemplates> v =
                        m_group.mod_order(R.get_affine_x());
                    return (v == r);
                }
            };

            template<typename CurveType>
            struct ecgdsa_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename CurveType::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename CurveType::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                template<typename Hash>
                inline static bool sign(signature_type &res, const number_type &val, const key_schedule_type &key) {
                    const ec_group m_group;
                    const boost::multiprecision::number<Backend, ExpressionTemplates> &m_x;
                    std::vector<boost::multiprecision::number<Backend, ExpressionTemplates>> m_ws;

                    //-----------------------
                    pk_operations::signature_with_emsa(emsa), m_group(ecgdsa.domain()),
                        m_x(ecgdsa.private_value())
                    //------------------------
                    const boost::multiprecision::number<Backend, ExpressionTemplates> m(msg, msg_len,
                        m_group.get_order_bits());

                    const boost::multiprecision::number<Backend, ExpressionTemplates> k = m_group.random_scalar(rng);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> r =
                        m_group.mod_order(m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                    const boost::multiprecision::number<Backend, ExpressionTemplates> kr =
                        m_group.multiply_mod_order(k, r);

                    const boost::multiprecision::number<Backend, ExpressionTemplates> s =
                        m_group.multiply_mod_order(m_x, kr - m);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if (r.is_zero() || s.is_zero()) {
                        throw internal_error("During ECGDSA signature generated zero r/s");
                    }

                    return boost::multiprecision::number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(
                        r, s, m_group.get_order_bytes());
                }
            };

            template<typename CurveType>
            struct ecgdsa {
                typedef CurveType curve_type;

                typedef ecgdsa_public_key<CurveType> public_key_policy;
                typedef ecgdsa_private_key<CurveType> private_key_policy;

                template<typename Hash>
                using padding_types = std::tuple<padding::emsa1<ecdsa<CurveType>, Hash>>;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

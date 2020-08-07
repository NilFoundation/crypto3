//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ECDSA_KEY_HPP
#define CRYPTO3_PUBKEY_ECDSA_KEY_HPP

#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/pubkey/detail/consistency.hpp>
#include <nil/crypto3/pubkey/detail/modes/rfc6979.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType>
            struct ecdsa_public_key {
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
                    if(sig_len != m_group.get_order_bytes() * 2)
                        return false;

                    const BigInt e(msg, msg_len, m_group.get_order_bits());

                    const BigInt r(sig, sig_len / 2);
                    const BigInt s(sig + sig_len / 2, sig_len / 2);

                    if(r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order())
                        return false;

                    const BigInt w = inverse_mod(s, m_group.get_order());

                    const BigInt u1 = m_group.multiply_mod_order(e, w);
                    const BigInt u2 = m_group.multiply_mod_order(r, w);
                    const PointGFp R = m_gy_mul.multi_exp(u1, u2);

                    if(R.is_zero())
                        return false;

                    const BigInt v = m_group.mod_order(R.get_affine_x());
                    return (v == r);

                }
            };

            template<typename CurveType>
            struct ecdsa_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename CurveType::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename CurveType::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                template<typename NonceGenerator>
                inline static bool sign(signature_type &res, const number_type &val, const key_schedule_type &key) {
                    BigInt m(msg, msg_len, m_group.get_order_bits());

//                    const BigInt k = generate_rfc6979_nonce(m_x, m_group.get_order(), m, m_rfc6979_hash);

                    const BigInt k_inv = inverse_mod(k, m_group.get_order());
                    const BigInt r = m_group.mod_order(
                        m_group.blinded_base_point_multiply_x(k, rng, m_ws));

                    const BigInt xrm = m_group.mod_order(m_group.multiply_mod_order(m_x, r) + m);
                    const BigInt s = m_group.multiply_mod_order(k_inv, xrm);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if(r.is_zero() || s.is_zero())
                        throw Internal_Error("During ECDSA signature generated zero r/s");

//                    return BigInt::encode_fixed_length_int_pair(r, s, m_group.get_order_bytes());
                    res = std::make_tuple(r, s);
                }
            };

            template<typename CurveType>
            struct ecdsa {
                typedef ecdsa_public_key<CurveType> public_key_type;
                typedef ecdsa_private_key<CurveType> private_key_type;

                constexpr static const std::size_t public_key_bits = public_key_type::key_bits;
                constexpr static const std::size_t private_key_bits = private_key_type::key_bits;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

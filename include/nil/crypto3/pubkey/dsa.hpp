//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_DSA_HPP
#define CRYPTO3_PUBKEY_DSA_HPP

#include <nil/crypto3/pubkey/detail/nonce_generator.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme, typename Hash>
                struct emsa1;
            }

            template<typename FieldType>
            struct dsa_public_key {
                typedef FieldType field_type;

                typedef typename field_type::value_type value_type;

                constexpr static const std::size_t key_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_type;

                constexpr static const std::size_t key_schedule_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_schedule_type;

                constexpr static const std::size_t signature_bits = field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool verify(const signature_type &val, const key_schedule_type &key) {
                    m_y = m_group.power_g_p(m_x);

                    const number<Backend, ExpressionTemplates> &q = m_group.get_q();
                    const size_t q_bytes = q.bytes();

                    if (sig_len != 2 * q_bytes || msg_len > q_bytes) {
                        return false;
                    }

                    number<Backend, ExpressionTemplates> r(sig, q_bytes);
                    number<Backend, ExpressionTemplates> s(sig + q_bytes, q_bytes);
                    number<Backend, ExpressionTemplates> i(msg, msg_len, q.bits());

                    if (r <= 0 || r >= q || s <= 0 || s >= q) {
                        return false;
                    }

                    s = inverse_mod(s, q);

                    const number<Backend, ExpressionTemplates> sr = m_mod_q.multiply(s, r);
                    const number<Backend, ExpressionTemplates> si = m_mod_q.multiply(s, i);

                    s = m_group.multi_exponentiate(si, m_y, sr);

                    return (m_mod_q.reduce(s) == r);
                }
            };

            template<typename FieldType>
            struct dsa_private_key {
                typedef FieldType field_type;

                typedef typename field_type::number_type number_type;
                typedef typename field_type::value_type value_type;

                constexpr static const std::size_t key_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_type;

                constexpr static const std::size_t key_schedule_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_schedule_type;

                constexpr static const std::size_t signature_bits = field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                template<typename NonceGenerator>
                inline static bool sign(signature_type &res, const number_type &val, const key_schedule_type &key,
                                        const number_type &k) {
                    const number_type &q = m_group.get_q();

                    number<Backend, ExpressionTemplates> i(msg, msg_len, q.bits());

                    while (i >= q) {
                        i -= q;
                    }

                    number_type k = NonceGenerator()(key, q, i);

                    //                    const number<Backend, ExpressionTemplates> k = (m_x, q, i,
                    //                                                                                              m_rfc6979_hash);
                    //                    const number<Backend, ExpressionTemplates> k =
                    //                        number<Backend, ExpressionTemplates>::random_integer(rng, 1, q);

                    number_type s = inverse_mod(k, q);
                    const number_type r = m_mod_q.reduce(m_group.power_g_p(k));

                    s = m_mod_q.multiply(s, m_x * r + i);

                    // With overwhelming probability, a bug rather than actual zero r/s
                    if (r == 0 || s == 0) {
                        throw internal_error("Computed zero r/s during DSA signature");
                    }

                    //                    return number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(r,
                    //                    s, q.bytes());
                    res = std::make_tuple(r, s);
                }
            };

            template<typename FieldType>
            struct dsa {
                typedef FieldType field_type;

                typedef dsa_public_key<FieldType> public_key_type;
                typedef dsa_private_key<FieldType> private_key_type;

                template<typename Hash>
                using padding_types = std::tuple<padding::emsa1<dsa<FieldType>, Hash>>;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

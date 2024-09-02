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

#ifndef CRYPTO3_PUBKEY_ELGAMAL_HPP
#define CRYPTO3_PUBKEY_ELGAMAL_HPP

#include <nil/crypto3/pubkey/dl_algorithm.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename FieldType>
            struct el_gamal_public_key {
                typedef FieldType field_type;

                typedef typename field_type::value_type value_type;

                constexpr static const std::size_t key_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_type;

                constexpr static const std::size_t key_schedule_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_schedule_type;

                constexpr static const std::size_t signature_bits = field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool encrypt(const signature_type &val, const key_schedule_type &key) {
                    number<Backend, ExpressionTemplates> m(msg, msg_len);

                    if (m >= m_group.get_p()) {
                        throw std::invalid_argument("ElGamal encryption: Input is too large");
                    }

                    const size_t k_bits = m_group.exponent_bits();
                    const number<Backend, ExpressionTemplates> k(rng, k_bits);

                    const number<Backend, ExpressionTemplates> a = m_group.power_g_p(k);
                    const number<Backend, ExpressionTemplates> b = m_group.multiply_mod_p(m, m_powermod_y_p(k));

                    return number<Backend, ExpressionTemplates>::encode_fixed_length_int_pair(a, b, m_group.p_bytes());
                }
            };

            template<typename FieldType>
            struct el_gamal_private_key {
                typedef FieldType field_type;

                typedef typename field_type::number_type number_type;
                typedef typename field_type::value_type value_type;

                constexpr static const std::size_t key_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_type;

                constexpr static const std::size_t key_schedule_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type key_schedule_type;

                constexpr static const std::size_t signature_bits = field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;

                inline static bool decrypt(signature_type &res, const number_type &val, const key_schedule_type &key) {
                    const dl_group m_group;
                    fixed_exponent_power_mod m_powermod_x_p;
                    blinder m_blinder;
                    //---------
                    m_group(key.get_group()), m_powermod_x_p(key.get_x(), m_group.get_p()),
                        m_blinder(
                            m_group.p(), rng, [](const number<Backend, ExpressionTemplates> &k) { return k; },
                            [this](const number<Backend, ExpressionTemplates> &k) { return m_powermod_x_p(k); }) {
                    }
                    //---------
                    m_y = m_group.power_g_p(m_x);

                    const size_t p_bytes = m_group.p_bytes();

                    if (msg_len != 2 * p_bytes) {
                        throw std::invalid_argument("ElGamal decryption: Invalid message");
                    }

                    number<Backend, ExpressionTemplates> a(msg, p_bytes);
                    const number<Backend, ExpressionTemplates> b(msg + p_bytes, p_bytes);

                    if (a >= m_group.p() || b >= m_group.get_p()) {
                        throw std::invalid_argument("ElGamal decryption: Invalid message");
                    }

                    a = m_blinder.blind(a);

                    const number<Backend, ExpressionTemplates> r =
                        m_group.multiply_mod_p(m_group.inverse_mod_p(m_powermod_x_p(a)), b);

                    return number<Backend, ExpressionTemplates>::encode_1363(m_blinder.unblind(r), p_bytes);
                }
            };

            template<typename FieldType>
            struct el_gamal {
                typedef FieldType field_type;

                typedef el_gamal_public_key<field_type> public_key_type;
                typedef el_gamal_private_key<field_type> private_key_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

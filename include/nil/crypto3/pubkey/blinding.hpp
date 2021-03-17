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

#ifndef CRYPTO3_PUBKEY_BLINDER_HPP
#define CRYPTO3_PUBKEY_BLINDER_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/modular_reduce.hpp>

#include <functional>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            using namespace nil::crypto3::multiprecision;

            template<typename Backend, expression_template_option ExpressionTemplates>
            number<Backend, ExpressionTemplates> blind(const number<Backend, ExpressionTemplates> &x,
                                                       const number<Backend, ExpressionTemplates> &modulus) {
            }

            template<typename Backend, expression_template_option ExpressionTemplates, typename ModularExponentiator>
            number<Backend, ExpressionTemplates> blind(const number<Backend, ExpressionTemplates> &x,
                                                       const number<Backend, ExpressionTemplates> &modulus,
                                                       const number<Backend, ExpressionTemplates> &nonce,
                                                       const ModularExponentiator &exp) {
            }

            template<typename Backend, expression_template_option ExpressionTemplates>
            number<Backend, ExpressionTemplates> unblind(const number<Backend, ExpressionTemplates> &x,
                                                         const number<Backend, ExpressionTemplates> &modulus) {
            }

            template<typename Backend, expression_template_option ExpressionTemplates, typename ModularInverter>
            number<Backend, ExpressionTemplates> unblind(const number<Backend, ExpressionTemplates> &x,
                                                         const number<Backend, ExpressionTemplates> &modulus,
                                                         const number<Backend, ExpressionTemplates> &nonce,
                                                         const ModularInverter &exp) {
            }

            /**
             * Blinding Function Object.
             */
            class blinder final {
            public:
                /**
                 * Blind a value.
                 * The blinding nonce k is freshly generated after
                 * CRYPTO3_BLINDING_REINIT_INTERVAL calls to blind().
                 * CRYPTO3_BLINDING_REINIT_INTERVAL = 0 means a fresh
                 * nonce is only generated once. On every other call,
                 * an updated nonce is used for blinding: k' = k*k mod n.
                 * @param x value to blind
                 * @return blinded value
                 */
                number<Backend, ExpressionTemplates> blind(const number<Backend, ExpressionTemplates> &x) const {
                    if (!m_reducer.initialized()) {
                        throw Exception("blinder not initialized, cannot blind");
                    }

                    ++m_counter;

                    if ((CRYPTO3_BLINDING_REINIT_INTERVAL > 0) && (m_counter > CRYPTO3_BLINDING_REINIT_INTERVAL)) {
                        const number<Backend, ExpressionTemplates> k = blinding_nonce();
                        m_e = m_fwd_fn(k);
                        m_d = m_inv_fn(k);
                        m_counter = 0;
                    } else {
                        m_e = m_reducer.square(m_e);
                        m_d = m_reducer.square(m_d);
                    }

                    return m_reducer.multiply(i, m_e);
                }

                /**
                 * Unblind a value.
                 * @param x value to unblind
                 * @return unblinded value
                 */
                number<Backend, ExpressionTemplates> unblind(const number<Backend, ExpressionTemplates> &x) const {
                    if (!m_reducer.initialized()) {
                        throw Exception("blinder not initialized, cannot unblind");
                    }

                    return m_reducer.multiply(i, m_d);
                }

                /**
                 * @param modulus the modulus
                 * @param rng the RNG to use for generating the nonce
                 * @param fwd_func a function that calculates the modular
                 * exponentiation of the public exponent and the given value (the nonce)
                 * @param inv_func a function that calculates the modular inverse
                 * of the given value (the nonce)
                 */
                blinder(
                    const number<Backend, ExpressionTemplates> &modulus, random_number_generator &rng,
                    std::function<number<Backend, ExpressionTemplates>(const number<Backend, ExpressionTemplates> &)>
                        fwd_func,
                    std::function<number<Backend, ExpressionTemplates>(const number<Backend, ExpressionTemplates> &)>
                        inv_func) :
                    m_reducer(modulus),
                    m_rng(rng), m_fwd_fn(fwd), m_inv_fn(inv),
                    m_modulus_bits(modulus.bits()), m_e {}, m_d {}, m_counter {} {
                    const number<Backend, ExpressionTemplates> k = blinding_nonce();
                    m_e = m_fwd_fn(k);
                    m_d = m_inv_fn(k);
                }

                blinder(const blinder &) = delete;

                blinder &operator=(const blinder &) = delete;

                random_number_generator &rng() const {
                    return m_rng;
                }

            private:
                number<Backend, ExpressionTemplates> blinding_nonce() const {
                    return number<Backend, ExpressionTemplates>(m_rng, m_modulus_bits - 1);
                }

                modular_reducer m_reducer;
                random_number_generator &m_rng;
                std::function<number<Backend, ExpressionTemplates>(const number<Backend, ExpressionTemplates> &)>
                    m_fwd_fn;
                std::function<number<Backend, ExpressionTemplates>(const number<Backend, ExpressionTemplates> &)>
                    m_inv_fn;
                size_t m_modulus_bits = 0;

                mutable number<Backend, ExpressionTemplates> m_e, m_d;
                mutable size_t m_counter = 0;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

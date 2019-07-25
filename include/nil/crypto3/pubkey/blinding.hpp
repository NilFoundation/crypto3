#ifndef CRYPTO3_PUBKEY_BLINDER_HPP
#define CRYPTO3_PUBKEY_BLINDER_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/modular_reduce.hpp>

#include <functional>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            using namespace boost::multiprecision;

            class random_number_generator;

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
                cpp_int blind(const cpp_int &x) const {
                    if (!m_reducer.initialized()) {
                        throw Exception("blinder not initialized, cannot blind");
                    }

                    ++m_counter;

                    if ((CRYPTO3_BLINDING_REINIT_INTERVAL > 0) && (m_counter > CRYPTO3_BLINDING_REINIT_INTERVAL)) {
                        const cpp_int k = blinding_nonce();
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
                cpp_int unblind(const cpp_int &x) const {
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
                blinder(const cpp_int &modulus, random_number_generator &rng,
                        std::function<cpp_int(const cpp_int &)> fwd_func,
                        std::function<cpp_int(const cpp_int &)> inv_func) :
                    m_reducer(modulus),
                    m_rng(rng), m_fwd_fn(fwd), m_inv_fn(inv),
                    m_modulus_bits(modulus.bits()), m_e {}, m_d {}, m_counter {} {
                    const cpp_int k = blinding_nonce();
                    m_e = m_fwd_fn(k);
                    m_d = m_inv_fn(k);
                }

                blinder(const blinder &) = delete;

                blinder &operator=(const blinder &) = delete;

                random_number_generator &rng() const {
                    return m_rng;
                }

            private:
                cpp_int blinding_nonce() const {
                    return cpp_int(m_rng, m_modulus_bits - 1);
                }

                modular_reducer m_reducer;
                random_number_generator &m_rng;
                std::function<cpp_int(const cpp_int &)> m_fwd_fn;
                std::function<cpp_int(const cpp_int &)> m_inv_fn;
                size_t m_modulus_bits = 0;

                mutable cpp_int m_e, m_d;
                mutable size_t m_counter = 0;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif

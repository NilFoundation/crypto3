#ifndef CRYPTO3_BLINDER_H_
#define CRYPTO3_BLINDER_H_

#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/multiprecision/modular_reduce.hpp>

#include <functional>

namespace nil {
    namespace crypto3 {

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
            cpp_int blind(const cpp_int &x) const;

            /**
            * Unblind a value.
            * @param x value to unblind
            * @return unblinded value
            */
            cpp_int unblind(const cpp_int &x) const;

            /**
            * @param modulus the modulus
            * @param rng the RNG to use for generating the nonce
            * @param fwd_func a function that calculates the modular
            * exponentiation of the public exponent and the given value (the nonce)
            * @param inv_func a function that calculates the modular inverse
            * of the given value (the nonce)
            */
            blinder(const cpp_int &modulus, random_number_generator &rng,
                    std::function<cpp_int(const cpp_int &)> fwd_func, std::function<cpp_int(const cpp_int &)> inv_func);

            blinder(const blinder &) = delete;

            blinder &operator=(const blinder &) = delete;

            random_number_generator &rng() const {
                return m_rng;
            }

        private:
            cpp_int blinding_nonce() const;

            modular_reducer m_reducer;
            random_number_generator &m_rng;
            std::function<cpp_int(const cpp_int &)> m_fwd_fn;
            std::function<cpp_int(const cpp_int &)> m_inv_fn;
            size_t m_modulus_bits = 0;

            mutable cpp_int m_e, m_d;
            mutable size_t m_counter = 0;
        };
    }
}

#endif

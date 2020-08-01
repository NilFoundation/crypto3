//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FF_CURVE_NIST_HPP
#define CRYPTO3_FF_CURVE_NIST_HPP

#include <memory>

#include <boost/multiprecision/cpp_int.hpp>

#include <boost/multiprecision/modular_inverse.hpp>
#include <boost/multiprecision/prime.hpp>

#include <nil/crypto3/algebra/curves/curve_gfp.hpp>

namespace nil {
    namespace crypto3 {
            /**
             * Treating this MPI as a sequence of 32-bit words in big-endian
             * order, return word i (or 0 if out of range)
             */
            inline uint32_t get_uint32_t(const number<Backend, ExpressionTemplates> &x, size_t i) {
#if (BOOST_ARCH_CURRENT_WORD_BITS == 32)
                return x.word_at(i);
#elif (BOOST_ARCH_CURRENT_WORD_BITS == 64)
                return static_cast<uint32_t>(x.word_at(i / 2) >> ((i % 2) * 32));
#else
#error "Not implemented"
#endif
            }

            /**
             * Treating this MPI as a sequence of 32-bit words in big-endian
             * order, set word i to the value x
             */
            template<typename T>
            inline void set_uint32_t(number<Backend, ExpressionTemplates> &x, size_t i, T v_in) {
                const uint32_t v = static_cast<uint32_t>(v_in);
#if (BOOST_ARCH_CURRENT_WORD_BITS == 32)
                x.set_word_at(i, v);
#elif (BOOST_ARCH_CURRENT_WORD_BITS == 64)
                const word shift_32 = (i % 2) * 32;
                const word w = (x.word_at(i / 2) & (static_cast<word>(0xFFFFFFFF) << (32 - shift_32))) |
                               (static_cast<word>(v) << shift_32);
                x.set_word_at(i / 2, w);
#else
#error "Not implemented"
#endif
            }

        }    // namespace detail

        template<std::size_t PSize, std::size_t WordBits>
        class curve_nist_policy {
        public:
            constexpr static const std::size_t word_bits = WordBits;
            constexpr static const std::size_t p_bits = PSize;
            constexpr static const std::size_t p_words = (p_bits + word_bits - 1) / word_bits;
        };

        template<typename Policy, typename NumberType>
        class curve_nist : public curve_gfp<NumberType> {
        public:
            typedef Policy policy_type;
            typedef typename policy_type::p_type p_type;

            typedef curve_gfp<NumberType> number_type;

            constexpr static const std::size_t word_bits = policy_type::word_bits;
            constexpr static const std::size_t p_bits = policy_type::p_bits;
            constexpr static const std::size_t p_words = policy_type::p_words;

            constexpr static const p_type p = policy_type::p;

            template<typename Backend, expression_template_option ExpressionTemplates>
            curve_nist(const number<Backend, ExpressionTemplates> &a,
                       const number<Backend, ExpressionTemplates> &b) :
                m_1(1),
                m_a(a), m_b(b) {
                // All Solinas prime curves are assumed a == -3
            }

            bool a_is_zero() const override {
                return false;
            }

            bool a_is_minus_3() const override {
                return true;
            }

            const number_type &get_a() const override {
                return m_a;
            }

            const number_type &get_b() const override {
                return m_b;
            }

            const number_type &get_1_rep() const override {
                return m_1;
            }

            size_t get_p_words() const override {
                return p_words;
            }

            size_t get_ws_size() const override {
                return 2 * p_words + 4;
            }

            const number_type &get_a_rep() const override {
                return m_a;
            }

            const number_type &get_b_rep() const override {
                return m_b;
            }

            bool is_one(const number_type &x) const override {
                return x == m_1;
            }

            void to_curve_rep(number_type &x) const override {
                redc_mod_p(x);
            }

            void from_curve_rep(number_type &x) const override {
                redc_mod_p(x);
            }

            number_type invert_element(const number_type &x, secure_vector<uint32_t> &ws) const override {
                CRYPTO3_UNUSED(ws);
                return inverse_mod(x, p);
            }

            void curve_mul_words(number_type &z, const uint32_t x_words[], const size_t x_size,
                                 const number_type &y, secure_vector<uint32_t> &ws) const override {
                CRYPTO3_DEBUG_ASSERT(y.sig_words() <= p_words);

                if (ws.size() < get_ws_size()) {
                    ws.resize(get_ws_size());
                }

                const size_t output_size = 2 * p_words + 2;
                if (z.size() < output_size) {
                    z.grow_to(output_size);
                }

                bigint_mul(z.mutable_data(), z.size(), x_words, x_size, std::min(p_words, x_size), y.data(),
                           y.size(), std::min(p_words, y.size()), ws.data(), ws.size());

                this->redc_mod_p(z, ws);
            }

            void curve_mul_tmp(number_type &x, const number_type &y, number_type &tmp,
                               secure_vector<uint32_t> &ws) const {
                curve_mul(tmp, x, y, ws);
                x.swap(tmp);
            }

            void curve_sqr_tmp(number_type &x, number_type &tmp, secure_vector<uint32_t> &ws) const {
                curve_sqr(tmp, x, ws);
                x.swap(tmp);
            }

            void curve_sqr_words(number_type &z, const uint32_t x_words[], size_t x_size,
                                 secure_vector<uint32_t> &ws) const override {
                if (ws.size() < get_ws_size()) {
                    ws.resize(get_ws_size());
                }

                const size_t output_size = 2 * p_words + 2;
                if (z.size() < output_size) {
                    z.grow_to(output_size);
                }

                bigint_sqr(z.mutable_data(), output_size, x_words, x_size, std::min(p_words, x_size), ws.data(),
                           ws.size());

                this->redc_mod_p(z, ws);
            }

            virtual const number_type &get_p() const override {
                return p;
            }

            virtual void redc_mod_p(number_type &z) const override {
                policy_type::redc_mod_p(z);
            }

        private:
            // Curve parameters
            number_type m_1;
            number_type m_a, m_b;
            // c of m_p.sig_words()
        };
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_FF_CURVE_NIST_HPP

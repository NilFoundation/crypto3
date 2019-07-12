#ifndef CRYPTO3_CURVE_GFP_MONTGOMERY_HPP
#define CRYPTO3_CURVE_GFP_MONTGOMERY_HPP

#include <cstdint>

#include <nil/crypto3/multiprecision/modular_reduce.hpp>
#include <nil/crypto3/multiprecision/modular_inverse.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_gfp.hpp>

namespace nil {
    namespace crypto3 {

        template<typename NumberType>
        class curve_montgomery : public curve_gfp<NumberType> {
        public:
            typedef typename curve_gfp<NumberType>::number_type number_type;

            constexpr static const std::size_t word_bits = NumberType::limb_bits;

            template<typename Backend, expression_template_option ExpressionTemplates>
            curve_montgomery(const number<Backend, ExpressionTemplates> &p,
                             const number<Backend, ExpressionTemplates> &a,
                             const number<Backend, ExpressionTemplates> &b) : m_p(p), m_a(a), m_b(b),
                    m_p_words(m_p.sig_words()), m_p_dash(monty_inverse(m_p.word_at(0))) {
                bit_set(m_r, m_p_words * word_bits);
                m_r = mod_redc(m_r, m_p);
                m_r2 = mod_redc(m_r * m_r, m_p);
                m_r3 = mod_redc(m_r * m_r2, m_p);

                m_a_r = mod_redc(m_r * m_a, m_p);
                m_b_r = mod_redc(m_r * m_b, m_p);

                m_a_is_zero = (m_a == 0);
                m_a_is_minus_3 = (m_a + 3 == m_p);
            }

            bool a_is_zero() const override {
                return m_a_is_zero;
            }

            bool a_is_minus_3() const override {
                return m_a_is_minus_3;
            }

            const number_type &get_a() const override {
                return m_a;
            }

            const number_type &get_b() const override {
                return m_b;
            }

            const number_type &get_p() const override {
                return m_p;
            }

            const number_type &get_a_rep() const override {
                return m_a_r;
            }

            const number_type &get_b_rep() const override {
                return m_b_r;
            }

            const number_type &get_1_rep() const override {
                return m_r;
            }

            bool is_one(const number_type &x) const override {
                return x == m_r;
            }

            unsigned long get_p_words() const override {
                return m_p_words;
            }

            unsigned long get_ws_size() const override {
                return 2 * m_p_words + 4;
            }

            void redc_mod_p(number_type &z, secure_vector <uint32_t> &ws) const override {
                reduce_below(z, m_p);
            }

            number_type invert_element(const number_type &x, secure_vector <uint32_t> &ws) const override {
                // Should we use Montgomery inverse instead?
                const number_type inv = inverse_mod(x, m_p);
                number_type res;
                curve_mul(res, inv, m_r3, ws);
                return res;
            }

            void to_curve_rep(number_type &x, secure_vector <uint32_t> &ws) const override {
                const number_type tx = x;
                curve_mul(x, tx, m_r2, ws);
            }

            void from_curve_rep(number_type &x, secure_vector <uint32_t> &ws) const override {
                if (ws.size() < get_ws_size()) {
                    ws.resize(get_ws_size());
                }

                const unsigned long output_size = 2 * m_p_words + 2;
                if (x.size() < output_size) {
                    x.grow_to(output_size);
                }

                bigint_monty_redc(x.mutable_data(), m_p.data(), m_p_words, m_p_dash, ws.data(), ws.size());
            }

            void curve_mul_words(number_type &z, const uint32_t x_words[], std::size_t x_size, const number_type &y,
                                 secure_vector <uint32_t> &ws) const override {
                CRYPTO3_DEBUG_ASSERT(y.sig_words() <= m_p_words);

                if (ws.size() < get_ws_size()) {
                    ws.resize(get_ws_size());
                }

                const unsigned long output_size = 2 * m_p_words + 2;
                if (z.size() < output_size) {
                    z.grow_to(output_size);
                }

                bigint_mul(z.mutable_data(), z.size(), x_words, x_size, std::min(m_p_words, x_size), y.data(), y.size(),
                        std::min(m_p_words, y.size()), ws.data(), ws.size());

                bigint_monty_redc(z.mutable_data(), m_p.data(), m_p_words, m_p_dash, ws.data(), ws.size());
            }

            void curve_sqr_words(number_type &z, const uint32_t x_words[], std::size_t x_size,
                                 secure_vector <uint32_t> &ws) const override {
                if (ws.size() < get_ws_size()) {
                    ws.resize(get_ws_size());
                }

                const unsigned long output_size = 2 * m_p_words + 2;
                if (z.size() < output_size) {
                    z.grow_to(output_size);
                }

                bigint_sqr(z.mutable_data(), z.size(), x_words, x_size, std::min(m_p_words, x_size), ws.data(),
                        ws.size());

                bigint_monty_redc(z.mutable_data(), m_p.data(), m_p_words, m_p_dash, ws.data(), ws.size());
            }

        private:
            number_type m_p;
            number_type m_a, m_b;
            number_type m_a_r, m_b_r;
            unsigned long m_p_words; // c of m_p.sig_words()

            // Montgomery parameters
            number_type m_r, m_r2, m_r3;
            uint32_t m_p_dash;

            bool m_a_is_zero;
            bool m_a_is_minus_3;
        };
    }
}

#endif //CRYPTO3_CURVE_GFP_MONTGOMERY_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_POINT_MUL_HPP
#define CRYPTO3_PUBKEY_POINT_MUL_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_gfp.hpp>
#include <nil/crypto3/pubkey/ec_group/point_gfp.hpp>

#include <nil/crypto3/utilities/ct_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace {
            /**
             * Round up
             * @param n a non-negative integer
             * @param align_to the alignment boundary
             * @return n rounded up to a multiple of align_to
             */
            inline size_t round_up(size_t n, size_t align_to) {
                BOOST_ASSERT_MSG(align_to != 0, "align_to must not be 0");

                if (n % align_to) {
                    n += align_to - (n % align_to);
                }
                return n;
            }
        }    // namespace
        constexpr static const std::size_t point_gfp_scalar_blinding_bits = 80;

        /*!
         * @tparam CurveType Represents @ref curve_gfp type
         */
        template<typename CurveType>
        class point_gfp_base_point_precompute {
        public:
            typedef CurveType curve_type;
            typedef typename curve_type::number_type number_type;

            template<typename Backend, expression_template_option ExpressionTemplates>
            point_gfp_base_point_precompute(const point_gfp<curve_type> &base_point, const modular_reducer &mod_order) :
                m_base_point(base_point), m_mod_order(mod_order), m_p_words(base_point.get_curve().p().sig_words()),
                m_T_size(base_point.get_curve().p().bits() + point_gfp_scalar_blinding_bits + 1) {
                std::vector<number_type> ws(point_gfp<curve_type>::WORKSPACE_SIZE);

                const size_t p_bits = base_point.get_curve().p().bits();

                /*
                 * Some of the curves (eg secp160k1) have an order slightly larger than
                 * the size of the prime modulus. In all cases they are at most 1 bit
                 * longer. The +1 compensates for this.
                 */
                const size_t T_bits = round_up(p_bits + point_gfp_scalar_blinding_bits + 1, 2) / 2;

                std::vector<point_gfp> T(3 * T_bits);
                T.resize(3 * T_bits);

                T[0] = base;
                T[1] = T[0];
                T[1].mult2(ws);
                T[2] = T[1];
                T[2].add(T[0], ws);

                for (size_t i = 1; i != T_bits; ++i) {
                    T[3 * i + 0] = T[3 * i - 2];
                    T[3 * i + 0].mult2(ws);
                    T[3 * i + 1] = T[3 * i + 0];
                    T[3 * i + 1].mult2(ws);
                    T[3 * i + 2] = T[3 * i + 1];
                    T[3 * i + 2].add(T[3 * i + 0], ws);
                }

                point_gfp<CurveType>::force_all_affine(T, ws[0].get_word_vector());

                m_W.resize(T.size() * 2 * m_p_words);

                word *p = &m_W[0];
                for (size_t i = 0; i != T.size(); ++i) {
                    T[i].get_x().encode_words(p, m_p_words);
                    p += m_p_words;
                    T[i].get_y().encode_words(p, m_p_words);
                    p += m_p_words;
                }
            }

            template<typename UniformRandomGenerator, typename Backend, expression_template_option ExpressionTemplates>
            point_gfp<curve_type> mul(const number<Backend, ExpressionTemplates> &k, UniformRandomGenerator &rng,
                                      const number<Backend, ExpressionTemplates> &group_order,
                                      std::vector<number<Backend, ExpressionTemplates>> &ws) const {
                if (k < 0) {
                    throw std::invalid_argument("point_gfp_base_point_precompute scalar must be positive");
                }

                // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
                const number<Backend, ExpressionTemplates> mask(rng, point_gfp_scalar_blinding_bits);

                // Instead of reducing k mod group order should we alter the mask size??
                const number<Backend, ExpressionTemplates> scalar = m_mod_order.reduce(k) + group_order * mask;

                const size_t windows = round_up(scalar.bits(), 2) / 2;

                const size_t elem_size = 2 * m_p_words;

                BOOST_ASSERT_MSG(windows <= m_W.size() / (3 * elem_size),
                                 "Precomputed sufficient values for scalar mult");

                point_gfp R = m_base_point.zero();

                if (ws.size() < point_gfp::WORKSPACE_SIZE) {
                    ws.resize(point_gfp::WORKSPACE_SIZE);
                }

                // the precomputed multiples are not secret so use std::vector
                std::vector<word> Wt(elem_size);

                for (size_t i = 0; i != windows; ++i) {
                    const size_t window = windows - i - 1;
                    const size_t base_addr = (3 * window) * elem_size;

                    const word w = scalar.get_substring(2 * window, 2);

                    const word w_is_1 = ct::is_equal<word>(w, 1);
                    const word w_is_2 = ct::is_equal<word>(w, 2);
                    const word w_is_3 = ct::is_equal<word>(w, 3);

                    for (size_t j = 0; j != elem_size; ++j) {
                        const word w1 = m_W[base_addr + 0 * elem_size + j];
                        const word w2 = m_W[base_addr + 1 * elem_size + j];
                        const word w3 = m_W[base_addr + 2 * elem_size + j];

                        Wt[j] = ct::select3<word>(w_is_1, w1, w_is_2, w2, w_is_3, w3, 0);
                    }

                    R.add_affine(&Wt[0], m_p_words, &Wt[m_p_words], m_p_words, ws);

                    if (i == 0) {
                        /*
                         * Since we start with the top bit of the exponent we know the
                         * first window must have a non-zero element, and thus R is
                         * now a point other than the point at infinity.
                         */
                        CRYPTO3_DEBUG_ASSERT(w != 0);
                        R.randomize_repr(rng, ws[0].get_word_vector());
                    }
                }

                CRYPTO3_DEBUG_ASSERT(R.on_the_curve());

                return R;
            }

        private:
            const point_gfp<curve_type> &m_base_point;
            const modular_reducer &m_mod_order;

            const size_t m_p_words;
            const size_t m_T_size;

            /*
             * This is a table of T_size * 3*p_word words
             */
            std::vector<word> m_W;
        };

        template<typename CurveType>
        class point_gfp_var_point_precompute {
        public:
            typedef CurveType curve_type;
            typedef typename curve_type::number_type number_type;

            template<typename Backend, expression_templates ExpressionTemplates>
            point_gfp_var_point_precompute(const point_gfp<CurveType> &point, random_number_generator &rng,
                                           std::vector<number<Backend, ExpressionTemplates>> &ws) :
                m_curve(point.get_curve()),
                m_p_words(m_curve.p().sig_words()), m_window_bits(4) {
                if (ws.size() < point_gfp::WORKSPACE_SIZE) {
                    ws.resize(point_gfp::WORKSPACE_SIZE);
                }

                std::vector<point_gfp> U(1U << m_window_bits);
                U[0] = point.zero();
                U[1] = point;

                for (size_t i = 2; i < U.size(); i += 2) {
                    U[i] = U[i / 2].double_of(ws);
                    U[i + 1] = U[i].plus(point, ws);
                }

                // Hack to handle blinded_point_multiply
                if (rng.is_seeded()) {
                    number<Backend, ExpressionTemplates> &mask = ws[0];
                    number<Backend, ExpressionTemplates> &mask2 = ws[1];
                    number<Backend, ExpressionTemplates> &mask3 = ws[2];
                    number<Backend, ExpressionTemplates> &new_x = ws[3];
                    number<Backend, ExpressionTemplates> &new_y = ws[4];
                    number<Backend, ExpressionTemplates> &new_z = ws[5];
                    secure_vector<word> &tmp = ws[6].get_word_vector();

                    const curve_gfp &curve = U[0].get_curve();

                    const size_t p_bits = curve.p().bits();

                    // Skipping zero point since it can't be randomized
                    for (size_t i = 1; i != U.size(); ++i) {
                        mask.randomize(rng, p_bits - 1, false);
                        // Easy way of ensuring mask != 0
                        boost::multiprecision::bit_set(mask, 0);

                        curve.sqr(mask2, mask, tmp);
                        curve.mul(mask3, mask, mask2, tmp);

                        curve.mul(new_x, U[i].get_x(), mask2, tmp);
                        curve.mul(new_y, U[i].get_y(), mask3, tmp);
                        curve.mul(new_z, U[i].get_z(), mask, tmp);

                        U[i].swap_coords(new_x, new_y, new_z);
                    }
                }

                m_T.resize(U.size() * 3 * m_p_words);

                word *p = &m_T[0];
                for (size_t i = 0; i != U.size(); ++i) {
                    U[i].get_x().encode_words(p, m_p_words);
                    U[i].get_y().encode_words(p + m_p_words, m_p_words);
                    U[i].get_z().encode_words(p + 2 * m_p_words, m_p_words);
                    p += 3 * m_p_words;
                }
            }

            template<typename Backend, expression_templates ExpressionTemplates>
            point_gfp mul(const number<Backend, ExpressionTemplates> &k, random_number_generator &rng,
                          const number<Backend, ExpressionTemplates> &group_order,
                          std::vector<number<Backend, ExpressionTemplates>> &ws) const {
                if (k < 0) {
                    throw std::invalid_argument("point_gfp_var_point_precompute scalar must be positive");
                }
                if (ws.size() < point_gfp::WORKSPACE_SIZE) {
                    ws.resize(point_gfp::WORKSPACE_SIZE);
                }

                // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
                const number<Backend, ExpressionTemplates> mask(rng, point_gfp_scalar_blinding_bits, false);
                const number<Backend, ExpressionTemplates> scalar = k + group_order * mask;

                const size_t elem_size = 3 * m_p_words;
                const size_t window_elems = (1ULL << m_window_bits);

                size_t windows = round_up(scalar.bits(), m_window_bits) / m_window_bits;
                point_gfp R(m_curve);
                secure_vector<word> e(elem_size);

                if (windows > 0) {
                    windows--;

                    const uint32_t w = scalar.get_substring(windows * m_window_bits, m_window_bits);

                    clear_mem(e.data(), e.size());
                    for (size_t i = 1; i != window_elems; ++i) {
                        const word wmask = ct::is_equal<word>(w, i);

                        for (size_t j = 0; j != elem_size; ++j) {
                            e[j] |= wmask & m_T[i * elem_size + j];
                        }
                    }

                    R.add(&e[0], m_p_words, &e[m_p_words], m_p_words, &e[2 * m_p_words], m_p_words, ws);

                    /*
                    Randomize after adding the first nibble as before the addition R
                    is zero, and we cannot effectively randomize the point
                    representation of the zero point.
                    */
                    R.randomize_repr(rng, ws[0].get_word_vector());
                }

                while (windows) {
                    R.mult2i(m_window_bits, ws);

                    const uint32_t w = scalar.get_substring((windows - 1) * m_window_bits, m_window_bits);

                    clear_mem(e.data(), e.size());
                    for (size_t i = 1; i != window_elems; ++i) {
                        const word wmask = ct::is_equal<word>(w, i);

                        for (size_t j = 0; j != elem_size; ++j) {
                            e[j] |= wmask & m_T[i * elem_size + j];
                        }
                    }

                    R.add(&e[0], m_p_words, &e[m_p_words], m_p_words, &e[2 * m_p_words], m_p_words, ws);

                    windows--;
                }

                CRYPTO3_DEBUG_ASSERT(R.on_the_curve());

                return R;
            }

        private:
            const curve_gfp<CurveType> m_curve;
            const size_t m_p_words;
            const size_t m_window_bits;

            /*
             * Table of 2^window_bits * 3*2*p_word words
             * Kept in locked vector since the base point might be sensitive
             * (normally isn't in most protocols but hard to say anything
             * categorically.)
             */
            secure_vector<word> m_T;
        };

        template<typename CurveType, typename NumberType = typename CurveType::number_type>
        class point_gfp_multi_point_precompute {
        public:
            typedef CurveType curve_type;
            typedef NumberType number_type;

            template<typename Backend, expression_template_option ExpressionTemplates>
            point_gfp_multi_point_precompute(const point_gfp<number<Backend, ExpressionTemplates>> &g1,
                                             const point_gfp<number<Backend, ExpressionTemplates>> &g2) {
                std::vector<number<Backend, ExpressionTemplates>> ws(point_gfp::WORKSPACE_SIZE);

                point_gfp x2 = x;
                x2.mult2(ws);

                const point_gfp x3(x2.plus(x, ws));

                point_gfp y2 = y;
                y2.mult2(ws);

                const point_gfp y3(y2.plus(y, ws));

                m_M.reserve(15);

                m_M.push_back(x);
                m_M.push_back(x2);
                m_M.push_back(x3);

                m_M.push_back(y);
                m_M.push_back(y.plus(x, ws));
                m_M.push_back(y.plus(x2, ws));
                m_M.push_back(y.plus(x3, ws));

                m_M.push_back(y2);
                m_M.push_back(y2.plus(x, ws));
                m_M.push_back(y2.plus(x2, ws));
                m_M.push_back(y2.plus(x3, ws));

                m_M.push_back(y3);
                m_M.push_back(y3.plus(x, ws));
                m_M.push_back(y3.plus(x2, ws));
                m_M.push_back(y3.plus(x3, ws));

                point_gfp::force_all_affine(m_M, ws[0].get_word_vector());
            }

            /*
             * Return (g1*k1 + g2*k2)
             * Not constant time, intended to use with public inputs
             */
            point_gfp<number<Backend, ExpressionTemplates>>
                multi_exp(const number<Backend, ExpressionTemplates> &k1,
                          const number<Backend, ExpressionTemplates> &k2) const {
                std::vector<number<Backend, ExpressionTemplates>> ws(point_gfp::WORKSPACE_SIZE);

                const size_t z_bits = round_up(std::max(z1.bits(), z2.bits()), 2);

                point_gfp H = m_M[0].zero();

                for (size_t i = 0; i != z_bits; i += 2) {
                    if (i > 0) {
                        H.mult2i(2, ws);
                    }

                    const uint8_t z1_b = z1.get_substring(z_bits - i - 2, 2);
                    const uint8_t z2_b = z2.get_substring(z_bits - i - 2, 2);

                    const uint8_t z12 = (4 * z2_b) + z1_b;

                    // This function is not intended to be const time
                    if (z12) {
                        H.add_affine(m_M[z12 - 1], ws);
                    }
                }

                if (z1 < 0 != z2 < 0) {
                    H.negate();
                }

                return H;
            }

        private:
            std::vector<point_gfp<number_type>> m_M;
        };

        /**
         * @brief ECC point multiexponentiation (Non const-time).
         * @param p1 a point
         * @param z1 a scalar
         * @param p2 a point
         * @param z2 a scalar
         * @result (p1 * z1 + p2 * z2)
         */
        template<typename Backend, expression_templates ExpressionTemplates>
        point_gfp<number<Backend, ExpressionTemplates>>
            multi_exponentiate(const point_gfp<number<Backend, ExpressionTemplates>> &p1,
                               const number<Backend, ExpressionTemplates> &z1,
                               const point_gfp<number<Backend, ExpressionTemplates>> &p2,
                               const number<Backend, ExpressionTemplates> &z2) {
            point_gfp_multi_point_precompute xy_mul(x, y);
            return xy_mul.multi_exp(z1, z2);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_POINT_MUL_HPP

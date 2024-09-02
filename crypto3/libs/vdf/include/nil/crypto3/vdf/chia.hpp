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

#ifndef CRYPTO3_VDF_CHIA_HPP
#define CRYPTO3_VDF_CHIA_HPP

#include <nil/crypto3/vdf/detail/chia_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace vdf {
            class chia {
                typedef detail::chia_functions policy_type;

            public:
#if defined(CRYPTO3_VDF_GMP) || defined(CRYPTO3_VDF_MPIR)

                template<typename T = mpz_t>
                using state_type = typename policy_type::state_type<T>;

                /*!
                 * @brief
                 * @tparam NumberType
                 * @tparam ExpressionTemplates
                 * @param state
                 * @param discriminant
                 * @param a
                 * @param b
                 */
                template<typename Integer, typename NumberType = mpz_t>
                static inline void make_state(state_type<NumberType> &state, NumberType discriminant) {
                    NumberType denom;
                    mpz_init(denom);
                    mpz_set_ui(state.form.a, 2);
                    mpz_set_ui(state.form.b, 1);
                    mpz_mul(state.form.c, state.form.b, state.form.b);
                    mpz_sub(state.form.c, state.form.c, d);
                    mpz_mul_ui(denom, state.form.a, 4);
                    mpz_fdiv_q(state.form.c, state.form.c, denom);
                    mpz_set(state.form.d, discriminant);
                    fast_reduce(state);
                    mpz_clear(denom);
                }

                template<typename NumberType = mpz_t>
                static inline state_type<NumberType> make_state(const NumberType &a, const NumberType &b,
                                                                const NumberType &discriminant) {
                    state_type<NumberType> state;
                    make_state(state, discriminant, a, b);
                    return state;
                }

                template<typename T, typename I>
                inline static void compute(state_type<T> &state, I itr) {
                    policy_type::discriminant_generator(state, d);

                    mpz_abs(state.L, state.form.d);
                    mpz_root(state.L, state.L, 4);

                    for (int i = 0; i < itr; i++) {
                        policy_type::nudupl(state);
                        policy_type::fast_reduce(state);
                    }
                }

#elif defined(CRYPTO3_VDF_FLINT)

                template<typename T = fmpz_t>
                using state_type = typename policy_type::state_type<T>;

                /*!
                 * @brief
                 * @tparam NumberType
                 * @tparam ExpressionTemplates
                 * @param state
                 * @param discriminant
                 * @param a
                 * @param b
                 */
                template<typename Integer, typename NumberType = fmpz_t>
                static inline void make_state(state_type<NumberType> &state, NumberType discriminant) {
                    NumberType denom;
                    fmpz_init(denom);
                    fmpz_set_ui(state.form.a, 2);
                    fmpz_set_ui(state.form.b, 1);
                    fmpz_mul(state.form.c, state.form.b, state.form.b);
                    fmpz_sub(state.form.c, state.form.c, d);
                    fmpz_mul_ui(denom, state.form.a, 4);
                    fmpz_fdiv_q(state.form.c, state.form.c, denom);
                    fmpz_set(state.form.d, discriminant);
                    fast_reduce(state);
                    fmpz_clear(denom);
                }

                template<typename NumberType = fmpz_t>
                static inline state_type<NumberType> make_state(NumberType a, NumberType b, NumberType discriminant) {
                    state_type<NumberType> state;
                    make_state(state, discriminant, a, b);
                    return state;
                }

                template<typename T, typename I>
                inline static void compute(state_type<T> &state, I itr) {
                    fmpz_abs(state.L, state.form.d);
                    fmpz_root(state.L, state.L, 4);

                    for (int i = 0; i < itr; i++) {
                        policy_type::nudupl(state);
                        policy_type::fast_reduce(state);
                    }
                }

#elif defined(CRYPTO3_VDF_BOOST)

                template<typename T>
                using state_type = typename policy_type::state_type<T>;

                /*!
                 * @brief
                 * @tparam Backend
                 * @tparam ExpressionTemplates
                 * @tparam Integer
                 * @param state
                 * @param difficulty
                 */
                template<typename Backend, expression_template_option ExpressionTemplates, typename Integer>
                inline static void compute(state_type<number<Backend, ExpressionTemplates>> &state,
                                           Integer difficulty) {
                    state.L = abs(state.form.d);
                    //#FIXME: requires root(state.L, 4) functions
                    state.L = sqrt(state.L);
                    state.L = sqrt(state.L);

                    for (int i = 0; i < difficulty; i++) {
                        policy_type::nudupl(state);
                        policy_type::fast_reduce(state);
                    }
                }

                /*!
                 * @brief
                 * @tparam Backend
                 * @tparam ExpressionTemplates
                 * @param state
                 * @param discriminant
                 * @param a
                 * @param b
                 */
                template<typename Backend, expression_template_option ExpressionTemplates>
                static inline void make_state(state_type<number<Backend, ExpressionTemplates>> &state,
                                              const number<Backend, ExpressionTemplates> &discriminant,
                                              const number<Backend, ExpressionTemplates> &a = 2,
                                              const number<Backend, ExpressionTemplates> &b = 1) {
                    state.form.a = a;
                    state.form.b = b;
                    state.form.c = (b * b - discriminant) / (a * 4);
                    state.form.d = discriminant;
                    policy_type::fast_reduce(state);
                }

                template<typename Backend, expression_template_option ExpressionTemplates>
                static inline state_type<number<Backend, ExpressionTemplates>>
                    make_state(const number<Backend, ExpressionTemplates> &a,
                               const number<Backend, ExpressionTemplates> &b,
                               const number<Backend, ExpressionTemplates> &discriminant) {
                    state_type<number<Backend, ExpressionTemplates>> state;
                    make_state(state, discriminant, a, b);
                    return state;
                }
#endif
            };
        }    // namespace vdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHIA_HPP

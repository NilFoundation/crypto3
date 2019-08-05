//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

                template<typename T, typename I>
                inline static void compute(state_type<T> &state, const T &d, I itr) {
                    policy_type::discriminant_generator(state, d);

                    mpz_abs(state.L, d);
                    mpz_root(state.L, state.L, 4);

                    for (int i = 0; i < itr; i++) {
                        policy_type::nudupl(state);
                        policy_type::fast_reduce(state);
                    }
                }

#elif defined(CRYPTO3_VDF_FLINT)

                template<typename T = fmpz_t>
                using state_type = typename policy_type::state_type<T>;

                template<typename T, typename I>
                inline static void compute(state_type<T> &state, const T &d, I itr) {
                    policy_type::discriminant_generator(state, d);

                    fmpz_abs(state.L, d);
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
                    state.L = std::abs()
                    fmpz_abs(state.L, difficulty);
                    fmpz_root(state.L, state.L, 4);

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
                    fast_reduce(state);
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

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

                template<typename Backend, expression_template_option ExpressionTemplates, typename Integer>
                inline static void compute(state_type<number<Backend, ExpressionTemplates>> &state,
                                           Integer difficulty) {
                    fmpz_abs(state.L, difficulty);
                    fmpz_root(state.L, state.L, 4);

                    for (int i = 0; i < difficulty; i++) {
                        policy_type::nudupl(state);
                        policy_type::fast_reduce(state);
                    }
                }

                template<typename Backend, expression_template_option ExpressionTemplates>
                static inline void state_from_discriminant(state_type<number<Backend, ExpressionTemplates>> &state,
                                                           const number<Backend, ExpressionTemplates> &d) {
                    number<Backend, ExpressionTemplates> denom;
                    mpz_set_ui(state.form.a, 2);
                    mpz_set_ui(state.form.b, 1);
                    mpz_set_ui(state.form.b, 1);
                    mpz_mul(state.form.c, state.form.b, state.form.b);
                    mpz_sub(state.form.c, state.form.c, d);
                    mpz_mul_ui(denom, state.form.a, 4);
                    mpz_fdiv_q(state.form.c, state.form.c, denom);
                    fast_reduce(state);
                    mpz_clear(denom);
                }

#endif
            };
        }    // namespace vdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHIA_HPP

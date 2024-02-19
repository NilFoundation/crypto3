//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP

#include <algorithm>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType>
                class placeholder_permutation_argument {

                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;

                    static constexpr std::size_t argument_size = 3;
                public:
                    // TODO: Check, do we really need permutation_polynomial_dfs.
                    struct prover_result_type {
                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;

                        math::polynomial_dfs<typename FieldType::value_type> permutation_polynomial_dfs;
                    };

                    static inline prover_result_type prove_eval(
                        const plonk_constraint_system<FieldType>
                            &constraint_system,
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type
                            preprocessed_data,
                        const plonk_table_description<FieldType>
                            &table_description,
                        const plonk_polynomial_dfs_table<FieldType>
                            &column_polynomials,
                        typename ParamsType::commitment_scheme_type& commitment_scheme,
                        transcript_type& transcript) {

                        PROFILE_PLACEHOLDER_SCOPE("permutation_argument_prove_eval_time");

                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_sigma =
                            preprocessed_data.permutation_polynomials;
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_id =
                            preprocessed_data.identity_polynomials;
                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            preprocessed_data.common_data.basic_domain;
                        // 1. $\beta_1, \gamma_1 = \challenge$
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        // 2. Calculate id_binding, sigma_binding for j from 1 to N_rows
                        // 3. Calculate $V_P$
                        math::polynomial_dfs<typename FieldType::value_type> V_P(basic_domain->size() - 1,
                                                                                 basic_domain->size());

                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> g_v = S_id;
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> h_v = S_sigma;
                        for (std::size_t i = 0; i < S_id.size(); i++) {
                            BOOST_ASSERT(column_polynomials[i].size() == basic_domain->size());
                            BOOST_ASSERT(S_id[i].size() == basic_domain->size());
                            BOOST_ASSERT(S_sigma[i].size() == basic_domain->size());

                            /* g_v.push_back(column_polynomials[i] + beta * S_id[i] + gamma); */
                            g_v[i] *= beta;
                            g_v[i] += gamma;
                            g_v[i] += column_polynomials[i];

                            /* h_v.push_back(column_polynomials[i] + beta * S_sigma[i] + gamma); */
                            h_v[i] *= beta;
                            h_v[i] += gamma;
                            h_v[i] += column_polynomials[i];
                        }

                        V_P[0] = FieldType::value_type::one();
                        for (std::size_t j = 1; j < basic_domain->size(); j++) {
                            typename FieldType::value_type nom = FieldType::value_type::one();
                            typename FieldType::value_type denom = FieldType::value_type::one();

                            for (std::size_t i = 0; i < S_id.size(); i++) {
                                nom *= g_v[i][j - 1];
                                denom *= h_v[i][j - 1];
                            }
                            V_P[j] = V_P[j - 1] * nom / denom;
                        }

                        // 4. Compute and add commitment to $V_P$ to $\text{transcript}$.
                        // TODO: Better enumeration for polynomial batches
                        commitment_scheme.append_to_batch(PERMUTATION_BATCH, V_P);

                        // 5. Calculate g_perm, h_perm
                        math::polynomial_dfs<typename FieldType::value_type> g =
                            math::polynomial_product<FieldType>(std::move(g_v));
                        math::polynomial_dfs<typename FieldType::value_type> h =
                            math::polynomial_product<FieldType>(std::move(h_v));

                        math::polynomial_dfs<typename FieldType::value_type> one_polynomial(
                            0, V_P.size(), FieldType::value_type::one());
                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;
                        math::polynomial_dfs<typename FieldType::value_type> V_P_shifted =
                            math::polynomial_shift(V_P, 1, basic_domain->m);

                        /* F_dfs[0] = preprocessed_data.common_data.lagrange_0 * (one_polynomial - V_P); */

                        F_dfs[0] = one_polynomial;
                        F_dfs[0] -= V_P;
                        F_dfs[0] *= preprocessed_data.common_data.lagrange_0;

                        /* F_dfs[1] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) * (V_P_shifted * h - V_P * g); */
                        math::polynomial_dfs<typename FieldType::value_type> t1 = V_P;
                        t1 *= g;
                        V_P_shifted *= h;
                        V_P_shifted -= t1;

                        F_dfs[1] = one_polynomial;
                        F_dfs[1] -= preprocessed_data.q_last;
                        F_dfs[1] -= preprocessed_data.q_blind;
                        F_dfs[1] *= V_P_shifted;

                        /* F_dfs[2] = preprocessed_data.q_last * V_P * (V_P - one_polynomial); */
                        F_dfs[2] = V_P;
                        F_dfs[2] -= one_polynomial;
                        F_dfs[2] *= V_P;
                        F_dfs[2] *= preprocessed_data.q_last;

                        prover_result_type res = {std::move(F_dfs), std::move(V_P)};

                        return res;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> verify_eval(
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type
                            &preprocessed_data,
                        // y
                        const typename FieldType::value_type &challenge,
                        // f(y):
                        const std::vector<typename FieldType::value_type> &column_polynomials_values,
                        // V_P(y):
                        const typename FieldType::value_type &perm_polynomial_value,
                        // V_P(omega * y):
                        const typename FieldType::value_type &perm_polynomial_shifted_value,
                        transcript_type &transcript) {

                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_sigma =
                            preprocessed_data.permutation_polynomials;
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_id =
                            preprocessed_data.identity_polynomials;

                        // 1. Get beta, gamma
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();
                        // 2. Add commitment to V_P to transcript

                        // 3. Calculate h_perm, g_perm at challenge point
                        math::polynomial_dfs<typename FieldType::value_type> one_polynomial(
                            0, preprocessed_data.common_data.basic_domain->size(), FieldType::value_type::one());
                        math::polynomial_dfs<typename FieldType::value_type> g_poly = one_polynomial;
                        math::polynomial_dfs<typename FieldType::value_type> h_poly = one_polynomial;

                        for (std::size_t i = 0; i < column_polynomials_values.size(); i++) {
                            typename FieldType::value_type pp = column_polynomials_values[i] + gamma;
                            math::polynomial_dfs<typename FieldType::value_type> t_id = S_id[i];
                            math::polynomial_dfs<typename FieldType::value_type> t_sigma = S_sigma[i];

                            //  g_poly = g_poly * (S_id[i] * beta + pp);
                            t_id *= beta;
                            t_id += pp;
                            g_poly *= t_id;

                            // h_poly = h_poly * (S_sigma[i] * beta  + pp);
                            t_sigma *= beta;
                            t_sigma += pp;
                            h_poly *= t_sigma;
                        }

                        std::array<typename FieldType::value_type, argument_size> F;
                        typename FieldType::value_type one = FieldType::value_type::one();

                        F[0] = preprocessed_data.common_data.lagrange_0.evaluate(challenge) *
                               (one - perm_polynomial_value);

                        // F[1] = ((one - preprocessed_data.q_last - preprocessed_data.q_blind) *
                        //       (perm_polynomial_shifted_value * h_poly - perm_polynomial_value * g_poly)).evaluate(challenge);
                        h_poly *= perm_polynomial_shifted_value;
                        g_poly *= perm_polynomial_value;
                        h_poly -= g_poly;
                        h_poly *= one - preprocessed_data.q_last - preprocessed_data.q_blind;
                        F[1] = h_poly.evaluate(challenge);

                        F[2] = preprocessed_data.q_last.evaluate(challenge) *
                               (perm_polynomial_value.squared() - perm_polynomial_value);

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP

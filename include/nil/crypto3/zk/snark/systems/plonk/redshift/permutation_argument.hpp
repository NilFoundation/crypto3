//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PERMUTATION_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PERMUTATION_ARGUMENT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename CommitmentSchemeType,
                    std::size_t witness_columns, std::size_t public_columns, 
                    typename TranscriptHashType = hashes::keccak_1600<512>>
                class redshift_permutation_argument {

                    using types_policy = detail::redshift_types_policy<FieldType, witness_columns, public_columns>;

                    typedef typename CommitmentSchemeType::fri_type fri_type;

                    static constexpr std::size_t argument_size = 3;

                public:
                    struct prover_result_type {
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;

                        math::polynomial<typename FieldType::value_type> permutation_polynomial;

                        typename CommitmentSchemeType::merkle_tree_type permutation_poly_commitment;
                    };

                    template<std::size_t table_width>
                    static inline prover_result_type
                        prove_eval(fiat_shamir_heuristic_updated<TranscriptHashType> &transcript,
                                   const typename types_policy::template preprocessed_data_type<witness_columns> preprocessed_data,
                                   const typename types_policy::template circuit_short_description<CommitmentSchemeType> &short_description,
                                   const std::array<math::polynomial<typename FieldType::value_type>, table_width> &columns,
                                   typename fri_type::params_type fri_params) {

                        const std::vector<math::polynomial<typename FieldType::value_type>> &S_sigma = preprocessed_data.permutation_polynomials;
                        const std::vector<math::polynomial<typename FieldType::value_type>> &S_id = preprocessed_data.identity_polynomials;
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain = preprocessed_data.basic_domain;

                        // 1. $\beta_1, \gamma_1 = \challenge$
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();

                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        // 2. Calculate id_binding, sigma_binding for j from 1 to N_rows
                        std::vector<typename FieldType::value_type> id_binding(short_description.table_rows);
                        std::vector<typename FieldType::value_type> sigma_binding(short_description.table_rows);

                        for (std::size_t j = 0; j < short_description.table_rows; j++) {
                            id_binding[j] = FieldType::value_type::one();
                            sigma_binding[j] = FieldType::value_type::one();
                            for (std::size_t i = 0; i < S_id.size(); i++) {

                                id_binding[j] *= (columns[i].evaluate(domain->get_domain_element(j)) +
                                                  beta * S_id[i].evaluate(domain->get_domain_element(j)) + gamma);
                                sigma_binding[j] *= (columns[i].evaluate(domain->get_domain_element(j)) +
                                                     beta * S_sigma[i].evaluate(domain->get_domain_element(j)) + gamma);
                            }
                        }

                        // 3. Calculate $V_P$
                        std::vector<typename FieldType::value_type> V_P_interpolation_points(short_description.table_rows);

                        V_P_interpolation_points[0] = FieldType::value_type::one();
                        for (std::size_t j = 1; j < short_description.table_rows; j++) {
                            typename FieldType::value_type tmp_mul_result = FieldType::value_type::one();
                            for (std::size_t i = 0; i <= j - 1; i++) {
                                // TODO: use one division
                                tmp_mul_result *= id_binding[i] / sigma_binding[i];
                            }

                            V_P_interpolation_points[j] = tmp_mul_result;
                        }

                        domain->inverse_fft(V_P_interpolation_points);

                        math::polynomial<typename FieldType::value_type> V_P(V_P_interpolation_points.begin(),
                                                                             V_P_interpolation_points.end());

                        // 4. Compute and add commitment to $V_P$ to $\text{transcript}$.
                        typename CommitmentSchemeType::merkle_tree_type V_P_tree =
                            CommitmentSchemeType::commit(V_P, fri_params.D[0]);
                        typename CommitmentSchemeType::commitment_type V_P_commitment = V_P_tree.root();
                        transcript(V_P_commitment);

                        // 5. Calculate g_perm, h_perm
                        math::polynomial<typename FieldType::value_type> g = {1};
                        math::polynomial<typename FieldType::value_type> h = {1};

                        for (std::size_t i = 0; i < S_id.size(); i++) {
                            g = g * (columns[i] + beta * S_id[i] + gamma);
                            h = h * (columns[i] + beta * S_sigma[i] + gamma);
                        }

                        math::polynomial<typename FieldType::value_type> one_polynomial = {1};
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;

                        math::polynomial<typename FieldType::value_type> V_P_shifted =
                            math::polynomial_shift<FieldType>(V_P, domain->get_domain_element(1));

                        F[0] = preprocessed_data.lagrange_0 * (one_polynomial - V_P);
                        F[1] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) * (V_P_shifted * h - V_P * g);
                        F[2] = preprocessed_data.q_last * (V_P * V_P - V_P);

                        prover_result_type res = {F, V_P, V_P_tree};

                        return res;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(fiat_shamir_heuristic_updated<TranscriptHashType> &transcript,
                                    const typename types_policy::template preprocessed_data_type<witness_columns> preprocessed_data,
                                    const typename types_policy::template circuit_short_description<CommitmentSchemeType> &short_description,
                                    const typename FieldType::value_type &challenge,                          // y
                                    const std::vector<typename FieldType::value_type> &column_polynomials,    // f(y)
                                    const typename FieldType::value_type &perm_polynomial,                    //
                                                                                                              // V_P(y)
                                    const typename FieldType::value_type &perm_polynomial_shifted,    // V_P(omega * y)
                                    const typename CommitmentSchemeType::commitment_type &V_P_commitment) {

                        const std::vector<math::polynomial<typename FieldType::value_type>> &S_sigma = preprocessed_data.permutation_polynomials;
                        const std::vector<math::polynomial<typename FieldType::value_type>> &S_id = preprocessed_data.identity_polynomials;

                        // 1. Get beta, gamma
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        // 2. Add commitment to V_P to transcript
                        transcript(V_P_commitment);

                        // 3. Calculate h_perm, g_perm at challenge point
                        typename FieldType::value_type g = FieldType::value_type::one();
                        typename FieldType::value_type h = FieldType::value_type::one();

                        for (std::size_t i = 0; i < column_polynomials.size(); i++) {
                            g = g * (column_polynomials[i] + beta * S_id[i].evaluate(challenge) + gamma);
                            h = h * (column_polynomials[i] + beta * S_sigma[i].evaluate(challenge) + gamma);
                        }

                        std::array<typename FieldType::value_type, argument_size> F;
                        typename FieldType::value_type one = FieldType::value_type::one();
                        F[0] = preprocessed_data.lagrange_0.evaluate(challenge) * (one - perm_polynomial);
                        F[1] = (one - preprocessed_data.q_last.evaluate(challenge) - preprocessed_data.q_blind.evaluate(challenge)) *
                               (perm_polynomial_shifted * h - perm_polynomial * g);
                        F[2] = preprocessed_data.q_last.evaluate(challenge) * (perm_polynomial.squared() - perm_polynomial);

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PERMUTATION_ARGUMENT_HPP
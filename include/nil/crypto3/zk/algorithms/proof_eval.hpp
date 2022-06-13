//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_SNARK_ALGORITHMS_PROOF_EVAL_HPP
#define CRYPTO3_ZK_SNARK_ALGORITHMS_PROOF_EVAL_HPP

#include <nil/crypto3/zk/algorithms/commit.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            // basic_fri
            template<typename CommitmentType,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_fri<typename CommitmentType::field_type,
                                                                        typename CommitmentType::merkle_tree_hash_type,
                                                                        typename CommitmentType::transcript_hash_type,
                                                                        CommitmentType::m>,
                                         CommitmentType>::value,
                         bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(math::polynomial_dfs<typename CommitmentType::field_type::value_type> f,
                           const math::polynomial_dfs<typename CommitmentType::field_type::value_type> &g,
                           typename CommitmentType::precommitment_type &T,
                           const typename CommitmentType::params_type &fri_params,
                           typename CommitmentType::transcript_type &transcript =
                               typename CommitmentType::transcript_type()) {

                transcript(commit<CommitmentType>(T));

                // TODO: how to sample x?
                std::size_t domain_size = fri_params.D[0]->size();
                f.resize(domain_size);
                std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                std::size_t r = fri_params.r;

                std::vector<typename CommitmentType::round_proof_type> round_proofs;
                std::unique_ptr<typename CommitmentType::merkle_tree_type> p_tree =
                    std::make_unique<typename CommitmentType::merkle_tree_type>(T);
                typename CommitmentType::merkle_tree_type T_next;

                for (std::size_t i = 0; i < r - 1; i++) {

                    std::size_t domain_size = fri_params.D[i]->size();

                    typename CommitmentType::field_type::value_type alpha =
                        transcript.template challenge<typename CommitmentType::field_type>();

                    x_index %= domain_size;

                    // m = 2, so:
                    std::array<std::size_t, CommitmentType::m> s_indices;
                    if constexpr (CommitmentType::m == 2) {
                        s_indices[0] = x_index;
                        s_indices[1] = (x_index + domain_size / 2) % domain_size;
                    } else {
                        return {};
                    }

                    std::array<typename CommitmentType::field_type::value_type, CommitmentType::m> y;
                    std::array<typename CommitmentType::merkle_proof_type, CommitmentType::m> p;

                    for (std::size_t j = 0; j < CommitmentType::m; j++) {
                        y[j] = (i == 0 ? g[s_indices[j]] : f[s_indices[j]]);
                        p[j] = typename CommitmentType::merkle_proof_type(*p_tree, s_indices[j]);
                    }

                    x_index %= fri_params.D[i + 1]->size();

                    // create polynomial of degree (degree(f) / 2)
                    if (i == 0) {
                        f.resize(fri_params.D[i]->size());
                    }
                    f = commitments::detail::fold_polynomial<typename CommitmentType::field_type>(
                        f, alpha, fri_params.D[i]);

                    typename CommitmentType::field_type::value_type colinear_value = f[x_index];

                    T_next = precommit<CommitmentType>(f, fri_params.D[i + 1]);    // new merkle tree
                    transcript(commit<CommitmentType>(T_next));

                    typename CommitmentType::merkle_proof_type colinear_path =
                        typename CommitmentType::merkle_proof_type(T_next, x_index);

                    round_proofs.push_back(typename CommitmentType::round_proof_type(
                        {y, p, p_tree->root(), colinear_value, colinear_path}));

                    p_tree = std::make_unique<typename CommitmentType::merkle_tree_type>(T_next);
                }

                math::polynomial<typename CommitmentType::field_type::value_type> f_normal(f.coefficients());
                return typename CommitmentType::proof_type({round_proofs, f_normal, commit<CommitmentType>(T)});
            }

            template<typename CommitmentType,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_fri<typename CommitmentType::field_type,
                                                                        typename CommitmentType::merkle_tree_hash_type,
                                                                        typename CommitmentType::transcript_hash_type,
                                                                        CommitmentType::m>,
                                         CommitmentType>::value,
                         bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(math::polynomial<typename CommitmentType::field_type::value_type> f,
                           const math::polynomial<typename CommitmentType::field_type::value_type> &g,
                           typename CommitmentType::precommitment_type &T,
                           const typename CommitmentType::params_type &fri_params,
                           typename CommitmentType::transcript_type &transcript =
                               typename CommitmentType::transcript_type()) {

                transcript(commit<CommitmentType>(T));

                // TODO: how to sample x?
                std::size_t domain_size = fri_params.D[0]->size();
                std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                typename CommitmentType::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

                std::size_t r = fri_params.r;

                std::vector<typename CommitmentType::round_proof_type> round_proofs;
                std::unique_ptr<typename CommitmentType::merkle_tree_type> p_tree =
                    std::make_unique<typename CommitmentType::merkle_tree_type>(T);
                typename CommitmentType::merkle_tree_type T_next;

                for (std::size_t i = 0; i < r - 1; i++) {

                    std::size_t domain_size = fri_params.D[i]->size();

                    typename CommitmentType::field_type::value_type alpha =
                        transcript.template challenge<typename CommitmentType::field_type>();

                    x_index %= domain_size;

                    // m = 2, so:
                    std::array<typename CommitmentType::field_type::value_type, CommitmentType::m> s;
                    std::array<std::size_t, CommitmentType::m> s_indices;
                    if constexpr (CommitmentType::m == 2) {
                        s[0] = x;
                        s[1] = -x;
                        s_indices[0] = x_index;
                        s_indices[1] = (x_index + domain_size / 2) % domain_size;
                    } else {
                        return {};
                    }

                    std::array<typename CommitmentType::field_type::value_type, CommitmentType::m> y;
                    std::array<typename CommitmentType::merkle_proof_type, CommitmentType::m> p;

                    for (std::size_t j = 0; j < CommitmentType::m; j++) {
                        y[j] = (i == 0 ? g.evaluate(s[j]) : f.evaluate(s[j]));    // polynomial evaluation
                        p[j] = typename CommitmentType::merkle_proof_type(*p_tree, s_indices[j]);
                    }

                    x_index %= fri_params.D[i + 1]->size();

                    x = fri_params.D[i + 1]->get_domain_element(x_index);

                    // create polynomial of degree (degree(f) / 2)
                    f = commitments::detail::fold_polynomial<typename CommitmentType::field_type>(f, alpha);

                    typename CommitmentType::field_type::value_type colinear_value =
                        f.evaluate(x);    // polynomial evaluation

                    T_next = precommit<CommitmentType>(f, fri_params.D[i + 1]);    // new merkle tree
                    transcript(commit<CommitmentType>(T_next));

                    typename CommitmentType::merkle_proof_type colinear_path =
                        typename CommitmentType::merkle_proof_type(T_next, x_index);

                    round_proofs.push_back(typename CommitmentType::round_proof_type(
                        {y, p, p_tree->root(), colinear_value, colinear_path}));

                    p_tree = std::make_unique<typename CommitmentType::merkle_tree_type>(T_next);
                }

                // last round contains only final_polynomial without queries
                return typename CommitmentType::proof_type({round_proofs, f, commit<CommitmentType>(T)});
            }

            // fri
            template<
                typename CommitmentType,
                typename PolynomialType,
                typename std::enable_if<std::is_base_of<commitments::fri<typename CommitmentType::field_type,
                                                                         typename CommitmentType::merkle_tree_hash_type,
                                                                         typename CommitmentType::transcript_hash_type,
                                                                         CommitmentType::m>,
                                                        CommitmentType>::value,
                                        bool>::type = true>
            static typename CommitmentType::basic_fri::proof_type
                proof_eval(const PolynomialType &g,
                           typename CommitmentType::precommitment_type &T,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                return proof_eval<typename CommitmentType::basic_fri>(g, g, T, fri_params, transcript);
            }
            // basic_batched_fri
            template<typename CommitmentType,
                     typename ContainerType,
                     typename std::enable_if<std::is_base_of<commitments::detail::basic_batched_fri<
                                                                 typename CommitmentType::field_type,
                                                                 typename CommitmentType::merkle_tree_hash_type,
                                                                 typename CommitmentType::transcript_hash_type,
                                                                 CommitmentType::m>,
                                                             CommitmentType>::value,
                                             bool>::type = true>
            static typename std::enable_if<
                (std::is_same<typename ContainerType::value_type,
                              math::polynomial_dfs<typename CommitmentType::field_type::value_type>>::value),
                typename CommitmentType::proof_type>::type
                proof_eval(
                    ContainerType f,
                    ContainerType g,
                    typename CommitmentType::precommitment_type &T,
                    const typename CommitmentType::params_type &fri_params,
                    typename CommitmentType::transcript_type &transcript = typename CommitmentType::transcript_type()) {

                for (int i = 0; i < f.size(); ++i) {
                    // assert(g[i].size() == fri_params.D[0]->size());
                    if (f[i].size() != fri_params.D[0]->size()) {
                        f[i].resize(fri_params.D[0]->size());
                    }
                    if (g[i].size() != fri_params.D[0]->size()) {
                        g[i].resize(fri_params.D[0]->size());
                    }
                }

                assert(f.size() == g.size());
                std::size_t leaf_size = f.size();

                transcript(commit<CommitmentType>(T));

                // TODO: how to sample x?
                std::size_t domain_size = fri_params.D[0]->size();
                std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                std::size_t r = fri_params.r;

                std::vector<typename CommitmentType::round_proof_type> round_proofs;
                std::unique_ptr<typename CommitmentType::merkle_tree_type> p_tree =
                    std::make_unique<typename CommitmentType::merkle_tree_type>(T);
                typename CommitmentType::merkle_tree_type T_next;

                for (std::size_t i = 0; i < r - 1; i++) {

                    std::size_t domain_size = fri_params.D[i]->size();

                    typename CommitmentType::field_type::value_type alpha =
                        transcript.template challenge<typename CommitmentType::field_type>();

                    x_index %= domain_size;

                    // m = 2, so:
                    std::array<std::size_t, CommitmentType::m> s_indices;
                    if constexpr (CommitmentType::m == 2) {
                        s_indices[0] = x_index;
                        s_indices[1] = (x_index + domain_size / 2) % domain_size;
                    } else {
                        return {};
                    }

                    // std::array<std::array<typename CommitmentType::field_type::value_type, m>, leaf_size> y;
                    std::vector<std::array<typename CommitmentType::field_type::value_type, CommitmentType::m>> y(
                        leaf_size);

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        for (std::size_t j = 0; j < CommitmentType::m; j++) {
                            y[polynom_index][j] = (i == 0 ? g[polynom_index][s_indices[j]] :
                                                            f[polynom_index][s_indices[j]]);    // polynomial evaluation
                        }
                    }

                    std::array<typename CommitmentType::merkle_proof_type, CommitmentType::m> p;

                    for (std::size_t j = 0; j < CommitmentType::m; j++) {

                        p[j] = typename CommitmentType::merkle_proof_type(*p_tree, s_indices[j]);
                    }

                    // std::array<typename CommitmentType::field_type::value_type, leaf_size> colinear_value;
                    std::vector<typename CommitmentType::field_type::value_type> colinear_value(leaf_size);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
//                                last = std::chrono::high_resolution_clock::now();
#endif
                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        if (i == 0) {
                            f[polynom_index].resize(fri_params.D[i]->size());
                        }
                        f[polynom_index] = commitments::detail::fold_polynomial<typename CommitmentType::field_type>(
                            f[polynom_index], alpha, fri_params.D[i]);
                    }

                    x_index = x_index % (fri_params.D[i + 1]->size());

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        colinear_value[polynom_index] = f[polynom_index][x_index];    // polynomial evaluation
                    }

                    T_next = precommit<CommitmentType>(f, fri_params.D[i + 1]);    // new merkle tree

                    transcript(commit<CommitmentType>(T_next));

                    typename CommitmentType::merkle_proof_type colinear_path =
                        typename CommitmentType::merkle_proof_type(T_next, x_index);

                    round_proofs.push_back(typename CommitmentType::round_proof_type(
                        {y, p, p_tree->root(), colinear_value, colinear_path}));

                    p_tree = std::make_unique<typename CommitmentType::merkle_tree_type>(T_next);
                }

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> final_polynomials(
                    f.size());

                for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
                    final_polynomials[polynom_index] =
                        math::polynomial<typename CommitmentType::field_type::value_type>(
                            f[polynom_index].coefficients());
                }

                return typename std::enable_if<
                    (std::is_same<typename ContainerType::value_type,
                                  math::polynomial_dfs<typename CommitmentType::field_type::value_type>>::value),
                    typename CommitmentType::proof_type>::type({round_proofs, final_polynomials,
                                                                commit<CommitmentType>(T)});
            }

            template<typename CommitmentType,
                     typename ContainerType,
                     typename std::enable_if<std::is_base_of<commitments::detail::basic_batched_fri<
                                                                 typename CommitmentType::field_type,
                                                                 typename CommitmentType::merkle_tree_hash_type,
                                                                 typename CommitmentType::transcript_hash_type,
                                                                 CommitmentType::m>,
                                                             CommitmentType>::value,
                                             bool>::type = true>
            static typename std::enable_if<
                (std::is_same<typename ContainerType::value_type,
                              math::polynomial<typename CommitmentType::field_type::value_type>>::value),
                typename CommitmentType::proof_type>::type
                proof_eval(
                    ContainerType f,
                    const ContainerType &g,
                    typename CommitmentType::precommitment_type &T,
                    const typename CommitmentType::params_type &fri_params,
                    typename CommitmentType::transcript_type &transcript = typename CommitmentType::transcript_type()) {

                assert(f.size() == g.size());
                std::size_t leaf_size = f.size();

                transcript(commit<CommitmentType>(T));

                // TODO: how to sample x?
                std::size_t domain_size = fri_params.D[0]->size();
                std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                typename CommitmentType::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

                std::size_t r = fri_params.r;

                std::vector<typename CommitmentType::round_proof_type> round_proofs;
                std::unique_ptr<typename CommitmentType::merkle_tree_type> p_tree =
                    std::make_unique<typename CommitmentType::merkle_tree_type>(T);
                typename CommitmentType::merkle_tree_type T_next;

                for (std::size_t i = 0; i < r - 1; i++) {

                    std::size_t domain_size = fri_params.D[i]->size();

                    typename CommitmentType::field_type::value_type alpha =
                        transcript.template challenge<typename CommitmentType::field_type>();

                    x_index %= domain_size;

                    // m = 2, so:
                    std::array<typename CommitmentType::field_type::value_type, CommitmentType::m> s;
                    std::array<std::size_t, CommitmentType::m> s_indices;
                    if constexpr (CommitmentType::m == 2) {
                        s[0] = x;
                        s[1] = -x;
                        s_indices[0] = x_index;
                        s_indices[1] = (x_index + domain_size / 2) % domain_size;
                    } else {
                        return {};
                    }

                    // std::array<std::array<typename CommitmentType::field_type::value_type, m>, leaf_size> y;
                    std::vector<std::array<typename CommitmentType::field_type::value_type, CommitmentType::m>> y(
                        leaf_size);

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        for (std::size_t j = 0; j < CommitmentType::m; j++) {
                            y[polynom_index][j] =
                                (i == 0 ? g[polynom_index].evaluate(s[j]) :
                                          f[polynom_index].evaluate(s[j]));    // polynomial evaluation
                        }
                    }

                    std::array<typename CommitmentType::merkle_proof_type, CommitmentType::m> p;

                    for (std::size_t j = 0; j < CommitmentType::m; j++) {

                        p[j] = typename CommitmentType::merkle_proof_type(*p_tree, s_indices[j]);
                    }

                    // std::array<typename CommitmentType::field_type::value_type, leaf_size> colinear_value;
                    std::vector<typename CommitmentType::field_type::value_type> colinear_value(leaf_size);

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        f[polynom_index] = commitments::detail::fold_polynomial<typename CommitmentType::field_type>(
                            f[polynom_index], alpha);
                    }

                    x_index = x_index % (fri_params.D[i + 1]->size());
                    x = fri_params.D[i + 1]->get_domain_element(x_index);

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        colinear_value[polynom_index] = f[polynom_index].evaluate(x);    // polynomial evaluation
                    }

                    T_next = precommit<CommitmentType>(f, fri_params.D[i + 1]);    // new merkle tree
                    transcript(commit<CommitmentType>(T_next));

                    typename CommitmentType::merkle_proof_type colinear_path =
                        typename CommitmentType::merkle_proof_type(T_next, x_index);

                    round_proofs.push_back(typename CommitmentType::round_proof_type(
                        {y, p, p_tree->root(), colinear_value, colinear_path}));

                    p_tree = std::make_unique<typename CommitmentType::merkle_tree_type>(T_next);
                }

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> final_polynomials(
                    f.begin(), f.end());

                return
                    typename CommitmentType::proof_type({round_proofs, final_polynomials, commit<CommitmentType>(T)});
            }
            // batched_fri
            template<typename CommitmentType,
                     typename ContainerType,
                     typename std::enable_if<std::is_base_of<commitments::detail::basic_batched_fri<
                                                                 typename CommitmentType::field_type,
                                                                 typename CommitmentType::merkle_tree_hash_type,
                                                                 typename CommitmentType::transcript_hash_type,
                                                                 CommitmentType::m>,
                                                             CommitmentType>::value,
                                             bool>::type = true>
            static typename CommitmentType::basic_fri::proof_type
                proof_eval(const ContainerType &g,
                           typename CommitmentType::precommitment_type &T,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                return proof_eval<typename CommitmentType::basic_fri>(g, g, T, fri_params, transcript);
            }
            // batched_list_polynomial_commitment
            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    CommitmentType::leaf_size,
                                                                                    false>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::array<std::vector<typename CommitmentType::field_type::value_type>,
                                            CommitmentType::leaf_size> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const std::array<math::polynomial_dfs<typename CommitmentType::field_type::value_type>,
                                            CommitmentType::leaf_size> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::array<std::vector<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size> z;
                std::array<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                 typename CommitmentType::field_type::value_type>>,
                           CommitmentType::leaf_size>
                    U_interpolation_points;

                std::array<math::polynomial<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size>
                    g_normal;
                for (int polynom_index = 0; polynom_index < g.size(); ++polynom_index) {
                    g_normal[polynom_index] = math::polynomial<typename CommitmentType::field_type::value_type>(
                        g[polynom_index].coefficients());
                }

                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());
                    z[polynom_index].resize(evaluation_points[polynom_index].size());

                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {

                        z[polynom_index][point_index] = g_normal[polynom_index].evaluate(
                            evaluation_points[polynom_index][point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[polynom_index][point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                std::array<math::polynomial<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size>
                    Q_normal;
                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q_normal[polynom_index] = (g_normal[polynom_index] - U);
                }

                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {
                        denominator_polynom =
                            denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                      -evaluation_points[polynom_index][point_index], 1};
                    }
                    Q_normal[polynom_index] = Q_normal[polynom_index] / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                std::array<math::polynomial_dfs<typename CommitmentType::field_type::value_type>,
                           CommitmentType::leaf_size>
                    Q;
                for (int polynom_index = 0; polynom_index < Q_normal.size(); ++polynom_index) {
                    Q[polynom_index].from_coefficients(Q_normal[polynom_index]);
                    Q[polynom_index].resize(fri_params.D[0]->size());
                }

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }

            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    CommitmentType::leaf_size,
                                                                                    false>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::array<std::vector<typename CommitmentType::field_type::value_type>,
                                            CommitmentType::leaf_size> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const std::array<math::polynomial<typename CommitmentType::field_type::value_type>,
                                            CommitmentType::leaf_size> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::array<std::vector<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size> z;
                std::array<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                 typename CommitmentType::field_type::value_type>>,
                           CommitmentType::leaf_size>
                    U_interpolation_points;

                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());
                    z[polynom_index].resize(evaluation_points[polynom_index].size());

                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {

                        z[polynom_index][point_index] = g[polynom_index].evaluate(
                            evaluation_points[polynom_index][point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[polynom_index][point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                std::array<math::polynomial<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size>
                    Q;
                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q[polynom_index] = (g[polynom_index] - U);
                }

                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {
                        denominator_polynom =
                            denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                      -evaluation_points[polynom_index][point_index], 1};
                    }
                    Q[polynom_index] = Q[polynom_index] / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }

            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    CommitmentType::leaf_size,
                                                                                    false>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::vector<typename CommitmentType::field_type::value_type> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const std::array<math::polynomial_dfs<typename CommitmentType::field_type::value_type>,
                                            CommitmentType::leaf_size> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::array<std::vector<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size> z;
                std::array<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                 typename CommitmentType::field_type::value_type>>,
                           CommitmentType::leaf_size>
                    U_interpolation_points;

                std::array<math::polynomial<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size>
                    g_normal;
                for (int polynom_index = 0; polynom_index < g.size(); ++polynom_index) {
                    g_normal[polynom_index] = math::polynomial<typename CommitmentType::field_type::value_type>(
                        g[polynom_index].coefficients());
                }

                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points.size());
                    z[polynom_index].resize(evaluation_points.size());

                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {

                        z[polynom_index][point_index] = g_normal[polynom_index].evaluate(
                            evaluation_points[point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                    denominator_polynom =
                        denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                  -evaluation_points[point_index], 1};
                }

                std::array<math::polynomial<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size>
                    Q_normal;
                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q_normal[polynom_index] = (g_normal[polynom_index] - U) / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                std::array<math::polynomial_dfs<typename CommitmentType::field_type::value_type>,
                           CommitmentType::leaf_size>
                    Q;
                for (int polynom_index = 0; polynom_index < Q_normal.size(); ++polynom_index) {
                    Q[polynom_index].from_coefficients(Q_normal[polynom_index]);
                    Q[polynom_index].resize(fri_params.D[0]->size());
                }

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        typename CommitmentType::basic_fri::proof_eval(Q, g, T, fri_params, transcript);
                }

                return proof_type({z, typename CommitmentType::basic_fri::commit(T), fri_proof});
            }

            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    CommitmentType::leaf_size,
                                                                                    false>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::vector<typename CommitmentType::field_type::value_type> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const std::array<math::polynomial<typename CommitmentType::field_type::value_type>,
                                            CommitmentType::leaf_size> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::array<std::vector<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size> z;
                std::array<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                 typename CommitmentType::field_type::value_type>>,
                           CommitmentType::leaf_size>
                    U_interpolation_points;

                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points.size());
                    z[polynom_index].resize(evaluation_points.size());

                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {

                        z[polynom_index][point_index] = g[polynom_index].evaluate(
                            evaluation_points[point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                    denominator_polynom =
                        denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                  -evaluation_points[point_index], 1};
                }

                std::array<math::polynomial<typename CommitmentType::field_type::value_type>, CommitmentType::leaf_size>
                    Q;
                for (std::size_t polynom_index = 0; polynom_index < CommitmentType::leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q[polynom_index] = (g[polynom_index] - U) / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        typename CommitmentType::basic_fri::proof_eval(Q, g, T, fri_params, transcript);
                }

                return proof_type({z, typename CommitmentType::basic_fri::commit(T), fri_proof});
            }
            // batched_list_polynomial_commitment<FieldType, LPCParams, 0, true>
            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    0,
                                                                                    true>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type proof_eval(
                const std::vector<std::vector<typename CommitmentType::field_type::value_type>> &evaluation_points,
                typename CommitmentType::precommitment_type &T,
                const std::vector<math::polynomial_dfs<typename CommitmentType::field_type::value_type>> &g,
                const typename CommitmentType::basic_fri::params_type &fri_params,
                typename CommitmentType::basic_fri::transcript_type &transcript =
                    typename CommitmentType::basic_fri::transcript_type()) {

                assert(evaluation_points.size() == g.size());
                std::size_t leaf_size = g.size();

                std::vector<std::vector<typename CommitmentType::field_type::value_type>> z(leaf_size);
                std::vector<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                  typename CommitmentType::field_type::value_type>>>
                    U_interpolation_points(leaf_size);

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> g_normal(leaf_size);
                for (int polynom_index = 0; polynom_index < leaf_size; ++polynom_index) {
                    g_normal[polynom_index] = math::polynomial<typename CommitmentType::field_type::value_type>(
                        g[polynom_index].coefficients());
                }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());
                    z[polynom_index].resize(evaluation_points[polynom_index].size());

                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {

                        z[polynom_index][point_index] = g_normal[polynom_index].evaluate(
                            evaluation_points[polynom_index][point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[polynom_index][point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> Q_normal(leaf_size);
                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q_normal[polynom_index] = (g_normal[polynom_index] - U);
                }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {
                        denominator_polynom =
                            denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                      -evaluation_points[polynom_index][point_index], 1};
                    }
                    Q_normal[polynom_index] = Q_normal[polynom_index] / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                std::vector<math::polynomial_dfs<typename CommitmentType::field_type::value_type>> Q(leaf_size);
                for (int polynom_index = 0; polynom_index < Q_normal.size(); ++polynom_index) {
                    Q[polynom_index].from_coefficients(Q_normal[polynom_index]);
                }

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }

            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    0,
                                                                                    true>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type proof_eval(
                const std::vector<std::vector<typename CommitmentType::field_type::value_type>> &evaluation_points,
                typename CommitmentType::precommitment_type &T,
                const std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> &g,
                const typename CommitmentType::basic_fri::params_type &fri_params,
                typename CommitmentType::basic_fri::transcript_type &transcript =
                    typename CommitmentType::basic_fri::transcript_type()) {

                assert(evaluation_points.size() == g.size());
                std::size_t leaf_size = g.size();

                std::vector<std::vector<typename CommitmentType::field_type::value_type>> z(leaf_size);
                std::vector<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                  typename CommitmentType::field_type::value_type>>>
                    U_interpolation_points(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());
                    z[polynom_index].resize(evaluation_points[polynom_index].size());

                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {

                        z[polynom_index][point_index] = g[polynom_index].evaluate(
                            evaluation_points[polynom_index][point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[polynom_index][point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> Q(leaf_size);
                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q[polynom_index] = (g[polynom_index] - U);
                }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {
                        denominator_polynom =
                            denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                      -evaluation_points[polynom_index][point_index], 1};
                    }
                    Q[polynom_index] = Q[polynom_index] / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }

            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    0,
                                                                                    true>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::vector<typename CommitmentType::field_type::value_type> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const std::vector<math::polynomial_dfs<typename CommitmentType::field_type::value_type>> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::size_t leaf_size = g.size();

                std::vector<std::vector<typename CommitmentType::field_type::value_type>> z(leaf_size);
                std::vector<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                  typename CommitmentType::field_type::value_type>>>
                    U_interpolation_points(leaf_size);

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> g_normal(leaf_size);
                for (int polynom_index = 0; polynom_index < leaf_size; ++polynom_index) {
                    g_normal[polynom_index] = math::polynomial<typename CommitmentType::field_type::value_type>(
                        g[polynom_index].coefficients());
                }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points.size());
                    z[polynom_index].resize(evaluation_points.size());

                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {

                        z[polynom_index][point_index] = g_normal[polynom_index].evaluate(
                            evaluation_points[point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> Q_normal(leaf_size);
                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q_normal[polynom_index] = (g_normal[polynom_index] - U);
                }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                        denominator_polynom =
                            denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                      -evaluation_points[point_index], 1};
                    }
                    Q_normal[polynom_index] = Q_normal[polynom_index] / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                std::vector<math::polynomial_dfs<typename CommitmentType::field_type::value_type>> Q(leaf_size);
                for (int polynom_index = 0; polynom_index < Q_normal.size(); ++polynom_index) {
                    Q[polynom_index].from_coefficients(Q_normal[polynom_index]);
                }

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }

            template<
                typename CommitmentType,
                typename std::enable_if<
                    std::is_base_of<commitments::batched_list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                    typename CommitmentType::lpc_params,
                                                                                    0,
                                                                                    true>,
                                    CommitmentType>::value,
                    bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::vector<typename CommitmentType::field_type::value_type> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::size_t leaf_size = g.size();

                std::vector<std::vector<typename CommitmentType::field_type::value_type>> z(leaf_size);
                std::vector<std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                                  typename CommitmentType::field_type::value_type>>>
                    U_interpolation_points(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U_interpolation_points[polynom_index].resize(evaluation_points.size());
                    z[polynom_index].resize(evaluation_points.size());

                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {

                        z[polynom_index][point_index] = g[polynom_index].evaluate(
                            evaluation_points[point_index]);    // transform to point-representation

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[point_index],
                                           z[polynom_index][point_index]);    // prepare points for interpolation
                    }
                }

                std::vector<math::polynomial<typename CommitmentType::field_type::value_type>> Q(leaf_size);
                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    math::polynomial<typename CommitmentType::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                    Q[polynom_index] = (g[polynom_index] - U);
                }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                        denominator_polynom =
                            denominator_polynom * math::polynomial<typename CommitmentType::field_type::value_type> {
                                                      -evaluation_points[point_index], 1};
                    }
                    Q[polynom_index] = Q[polynom_index] / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        typename CommitmentType::basic_fri::proof_eval(Q, g, T, fri_params, transcript);
                }

                return proof_type({z, typename CommitmentType::basic_fri::commit(T), fri_proof});
            }
            // list_polynomial_commitment
            template<typename CommitmentType,
                     typename std::enable_if<
                         std::is_base_of<commitments::list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                 typename CommitmentType::lpc_params>,
                                         CommitmentType>::value,
                         bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::vector<typename CommitmentType::field_type::value_type> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const math::polynomial_dfs<typename CommitmentType::field_type::value_type> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::size_t k = evaluation_points.size();
                std::vector<typename CommitmentType::field_type::value_type> z(k);
                std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                      typename CommitmentType::field_type::value_type>>
                    U_interpolation_points(k);

                math::polynomial<typename CommitmentType::field_type::value_type> g_normal(g.coefficients());

                for (std::size_t j = 0; j < k; j++) {
                    z[j] = g_normal.evaluate(evaluation_points[j]);    // transform to point-representation
                    U_interpolation_points[j] =
                        std::make_pair(evaluation_points[j], z[j]);    // prepare points for interpolation
                }

                math::polynomial<typename CommitmentType::field_type::value_type> U =
                    math::lagrange_interpolation(U_interpolation_points);    // k is small => iterpolation goes fast

                math::polynomial<typename CommitmentType::field_type::value_type> Q_normal = (g_normal - U);
                for (std::size_t j = 0; j < k; j++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {
                        -evaluation_points[j], 1};

                    Q_normal = Q_normal / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                math::polynomial_dfs<typename CommitmentType::field_type::value_type> Q;
                Q.from_coefficients(Q_normal);

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }

            template<typename CommitmentType,
                     typename std::enable_if<
                         std::is_base_of<commitments::list_polynomial_commitment<typename CommitmentType::field_type,
                                                                                 typename CommitmentType::lpc_params>,
                                         CommitmentType>::value,
                         bool>::type = true>
            static typename CommitmentType::proof_type
                proof_eval(const std::vector<typename CommitmentType::field_type::value_type> &evaluation_points,
                           typename CommitmentType::precommitment_type &T,
                           const math::polynomial<typename CommitmentType::field_type::value_type> &g,
                           const typename CommitmentType::basic_fri::params_type &fri_params,
                           typename CommitmentType::basic_fri::transcript_type &transcript =
                               typename CommitmentType::basic_fri::transcript_type()) {

                std::size_t k = evaluation_points.size();
                std::vector<typename CommitmentType::field_type::value_type> z(k);
                std::vector<std::pair<typename CommitmentType::field_type::value_type,
                                      typename CommitmentType::field_type::value_type>>
                    U_interpolation_points(k);

                for (std::size_t j = 0; j < k; j++) {
                    z[j] = g.evaluate(evaluation_points[j]);    // transform to point-representation
                    U_interpolation_points[j] =
                        std::make_pair(evaluation_points[j], z[j]);    // prepare points for interpolation
                }

                math::polynomial<typename CommitmentType::field_type::value_type> U =
                    math::lagrange_interpolation(U_interpolation_points);    // k is small => iterpolation goes fast

                math::polynomial<typename CommitmentType::field_type::value_type> Q = (g - U);
                for (std::size_t j = 0; j < k; j++) {
                    math::polynomial<typename CommitmentType::field_type::value_type> denominator_polynom = {
                        -evaluation_points[j], 1};
                    Q = Q / denominator_polynom;
                }

                std::array<typename CommitmentType::basic_fri::proof_type, CommitmentType::lambda> fri_proof;

                for (std::size_t round_id = 0; round_id <= CommitmentType::lambda - 1; round_id++) {
                    fri_proof[round_id] =
                        proof_eval<typename CommitmentType::basic_fri>(Q, g, T, fri_params, transcript);
                }

                return
                    typename CommitmentType::proof_type({z, commit<typename CommitmentType::basic_fri>(T), fri_proof});
            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ALGORITHMS_PROOF_EVAL_HPP

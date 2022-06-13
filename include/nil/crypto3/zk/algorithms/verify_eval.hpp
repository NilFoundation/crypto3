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

#ifndef CRYPTO3_ZK_SNARK_ALGORITHMS_VERIFY_EVAL_HPP
#define CRYPTO3_ZK_SNARK_ALGORITHMS_VERIFY_EVAL_HPP

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            // basic_fri
            template<typename FRI,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                        typename FRI::merkle_tree_hash_type,
                                                                        typename FRI::transcript_hash_type,
                                                                        FRI::m>,
                                         FRI>::value,
                         bool>::type = true>
            static bool verify_eval(typename FRI::proof_type &proof,
                                    typename FRI::params_type &fri_params,
                                    const math::polynomial<typename FRI::field_type::value_type> &U,
                                    const math::polynomial<typename FRI::field_type::value_type> &V,
                                    typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {

                transcript(proof.target_commitment);

                std::uint64_t idx = transcript.template int_challenge<std::uint64_t>();
                typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(idx);

                std::size_t r = fri_params.r;

                for (std::size_t i = 0; i < r - 1; i++) {
                    typename FRI::field_type::value_type alpha =
                        transcript.template challenge<typename FRI::field_type>();

                    // m = 2, so:
                    std::array<typename FRI::field_type::value_type, FRI::m> s;
                    if constexpr (FRI::m == 2) {
                        s[0] = x;
                        s[1] = -x;
                    } else {
                        return false;
                    }

                    for (std::size_t j = 0; j < FRI::m; j++) {
                        typename FRI::field_type::value_type leaf = proof.round_proofs[i].y[j];

                        std::array<std::uint8_t, FRI::field_element_type::length()> leaf_data;

                        typename FRI::field_element_type leaf_val(leaf);
                        auto write_iter = leaf_data.begin();
                        leaf_val.write(write_iter, FRI::field_element_type::length());

                        if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                            return false;
                        }
                    }

                    std::array<typename FRI::field_type::value_type, FRI::m> y;

                    for (std::size_t j = 0; j < FRI::m; j++) {
                        if (i == 0) {
                            y[j] = (proof.round_proofs[i].y[j] - U.evaluate(s[j])) / V.evaluate(s[j]);
                        } else {
                            y[j] = proof.round_proofs[i].y[j];
                        }
                    }

                    std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>
                        interpolation_points {
                            std::make_pair(s[0], y[0]),
                            std::make_pair(s[1], y[1]),
                        };

                    math::polynomial<typename FRI::field_type::value_type> interpolant =
                        math::lagrange_interpolation(interpolation_points);

                    typename FRI::field_type::value_type leaf = proof.round_proofs[i].colinear_value;

                    std::array<std::uint8_t, FRI::field_element_type::length()> leaf_data;
                    typename FRI::field_element_type leaf_val(leaf);
                    auto write_iter = leaf_data.begin();
                    leaf_val.write(write_iter, FRI::field_element_type::length());

                    if (interpolant.evaluate(alpha) != proof.round_proofs[i].colinear_value) {
                        return false;
                    }
                    transcript(proof.round_proofs[i].colinear_path.root());
                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                        return false;
                    }
                    x = x * x;
                }

                // check the final polynomial against its root
                auto final_root = commit<FRI>(precommit<FRI>(proof.final_polynomial, fri_params.D[r - 1]));
                if (final_root != proof.round_proofs[r - 2].colinear_path.root()) {
                    return false;
                }
                if (proof.final_polynomial.degree() > std::pow(2, std::log2(fri_params.max_degree + 1) - r + 1) - 1) {
                    return false;
                }

                return true;
            }

            // fri
            template<typename FRI,
                     typename std::enable_if<std::is_base_of<commitments::fri<typename FRI::field_type,
                                                                              typename FRI::merkle_tree_hash_type,
                                                                              typename FRI::transcript_hash_type,
                                                                              FRI::m>,
                                                             FRI>::value,
                                             bool>::type = true>
            static bool verify_eval(
                typename FRI::basic_fri::proof_type &proof,
                typename FRI::basic_fri::params_type &fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                math::polynomial<typename FRI::field_type::value_type> U = {0};
                math::polynomial<typename FRI::field_type::value_type> V = {1};
                return verify_eval<typename FRI::basic_fri>(proof, fri_params, U, V, transcript);
            }
            // basic_batched_fri
            template<typename FRI,
                     typename ContainerType,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                typename FRI::merkle_tree_hash_type,
                                                                                typename FRI::transcript_hash_type,
                                                                                FRI::m>,
                                         FRI>::value,
                         bool>::type = true>
            static bool verify_eval(typename FRI::proof_type &proof,
                                    typename FRI::params_type &fri_params,
                                    const ContainerType U,
                                    const ContainerType V,
                                    typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {

                assert(U.size() == V.size());
                std::size_t leaf_size = U.size();

                transcript(proof.target_commitment);

                std::size_t domain_size = fri_params.D[0]->size();
                std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

                std::size_t r = fri_params.r;

                for (std::size_t i = 0; i < r - 1; i++) {
                    typename FRI::field_type::value_type alpha =
                        transcript.template challenge<typename FRI::field_type>();

                    typename FRI::field_type::value_type x_next = x * x;

                    // m = 2, so:
                    std::array<typename FRI::field_type::value_type, FRI::m> s;
                    if constexpr (FRI::m == 2) {
                        s[0] = x;
                        s[1] = -x;
                    } else {
                        return false;
                    }

                    for (std::size_t j = 0; j < FRI::m; j++) {
                        std::vector<std::uint8_t> leaf_data(FRI::field_element_type::length() * leaf_size);

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                            typename FRI::field_type::value_type leaf = proof.round_proofs[i].y[polynom_index][j];

                            typename FRI::field_element_type leaf_val(leaf);
                            auto write_iter = leaf_data.begin() + FRI::field_element_type::length() * polynom_index;
                            leaf_val.write(write_iter, FRI::field_element_type::length());
                        }

                        if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                            return false;
                        }
                    }

                    std::vector<std::uint8_t> leaf_data(FRI::field_element_type::length() * leaf_size);

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                        std::array<typename FRI::field_type::value_type, FRI::m> y;

                        for (std::size_t j = 0; j < FRI::m; j++) {
                            if (i == 0) {
                                y[j] = (proof.round_proofs[i].y[polynom_index][j] - U[polynom_index].evaluate(s[j])) /
                                       V[polynom_index].evaluate(s[j]);
                            } else {
                                y[j] = proof.round_proofs[i].y[polynom_index][j];
                            }
                        }

                        std::vector<
                            std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>
                            interpolation_points {
                                std::make_pair(s[0], y[0]),
                                std::make_pair(s[1], y[1]),
                            };

                        math::polynomial<typename FRI::field_type::value_type> interpolant =
                            math::lagrange_interpolation(interpolation_points);

                        typename FRI::field_type::value_type leaf = proof.round_proofs[i].colinear_value[polynom_index];

                        typename FRI::field_element_type leaf_val(leaf);
                        auto write_iter = leaf_data.begin() + FRI::field_element_type::length() * polynom_index;
                        leaf_val.write(write_iter, FRI::field_element_type::length());

                        if (interpolant.evaluate(alpha) != proof.round_proofs[i].colinear_value[polynom_index]) {
                            return false;
                        }
                    }

                    transcript(proof.round_proofs[i].colinear_path.root());
                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                        return false;
                    }
                    x = x_next;
                }

                // auto final_root = commit(precommit(proof.final_polynomials, fri_params.D[r - 1]));
                // if (final_root != proof.round_proofs[r - 2].colinear_path.root()) {
                //     return false;
                // }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    if (proof.final_polynomials[polynom_index].degree() >
                        std::pow(2, std::log2(fri_params.max_degree + 1) - r + 1) - 1) {
                        return false;
                    }
                }

                return true;
            }

            template<typename FRI,
                     typename ContainerType,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                typename FRI::merkle_tree_hash_type,
                                                                                typename FRI::transcript_hash_type,
                                                                                FRI::m>,
                                         FRI>::value,
                         bool>::type = true>
            static bool verify_eval(typename FRI::proof_type &proof,
                                    typename FRI::params_type &fri_params,
                                    const ContainerType U,
                                    const math::polynomial<typename FRI::field_type::value_type>
                                        V,
                                    typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {

                std::size_t leaf_size = U.size();
                transcript(proof.target_commitment);

                std::size_t domain_size = fri_params.D[0]->size();
                std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

                std::size_t r = fri_params.r;

                for (std::size_t i = 0; i < r - 1; i++) {
                    typename FRI::field_type::value_type alpha =
                        transcript.template challenge<typename FRI::field_type>();

                    typename FRI::field_type::value_type x_next = x * x;

                    // m = 2, so:
                    std::array<typename FRI::field_type::value_type, FRI::m> s;
                    if constexpr (FRI::m == 2) {
                        s[0] = x;
                        s[1] = -x;
                    } else {
                        return false;
                    }

                    for (std::size_t j = 0; j < FRI::m; j++) {
                        std::vector<std::uint8_t> leaf_data(FRI::field_element_type::length() * leaf_size);

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                            typename FRI::field_type::value_type leaf = proof.round_proofs[i].y[polynom_index][j];

                            typename FRI::field_element_type leaf_val(leaf);
                            auto write_iter = leaf_data.begin() + FRI::field_element_type::length() * polynom_index;
                            leaf_val.write(write_iter, FRI::field_element_type::length());
                        }

                        if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                            return false;
                        }
                    }

                    std::vector<std::uint8_t> leaf_data(FRI::field_element_type::length() * leaf_size);

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                        std::array<typename FRI::field_type::value_type, FRI::m> y;

                        for (std::size_t j = 0; j < FRI::m; j++) {
                            if (i == 0) {
                                y[j] = (proof.round_proofs[i].y[polynom_index][j] - U[polynom_index].evaluate(s[j])) /
                                       V.evaluate(s[j]);
                            } else {
                                y[j] = proof.round_proofs[i].y[polynom_index][j];
                            }
                        }

                        std::vector<
                            std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>
                            interpolation_points {
                                std::make_pair(s[0], y[0]),
                                std::make_pair(s[1], y[1]),
                            };

                        math::polynomial<typename FRI::field_type::value_type> interpolant =
                            math::lagrange_interpolation(interpolation_points);

                        typename FRI::field_type::value_type leaf = proof.round_proofs[i].colinear_value[polynom_index];

                        typename FRI::field_element_type leaf_val(leaf);
                        auto write_iter = leaf_data.begin() + FRI::field_element_type::length() * polynom_index;
                        leaf_val.write(write_iter, FRI::field_element_type::length());

                        if (interpolant.evaluate(alpha) != proof.round_proofs[i].colinear_value[polynom_index]) {
                            return false;
                        }
                    }

                    transcript(proof.round_proofs[i].colinear_path.root());
                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                        return false;
                    }

                    x = x_next;
                }

                // auto final_root = commit(precommit(proof.final_polynomials, fri_params.D[r - 1]));
                // if (final_root != proof.round_proofs[r - 2].colinear_path.root()) {
                //     return false;
                // }

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    if (proof.final_polynomials[polynom_index].degree() >
                        std::pow(2, std::log2(fri_params.max_degree + 1) - r + 1) - 1) {
                        return false;
                    }
                }

                return true;
            }
            // batched_fri
            template<typename FRI,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                typename FRI::merkle_tree_hash_type,
                                                                                typename FRI::transcript_hash_type,
                                                                                FRI::m>,
                                         FRI>::value,
                         bool>::type = true>
            static bool verify_eval(
                typename FRI::basic_fri::proof_type &proof,
                typename FRI::basic_fri::params_type &fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                std::size_t leaf_size = proof.final_polynomials.size();

                std::vector<math::polynomial<typename FRI::field_type::value_type>> U(leaf_size);
                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U[polynom_index] = {0};
                }

                math::polynomial<typename FRI::field_type::value_type> V = {1};

                return verify_eval<typename FRI::basic_fri>(proof, fri_params, U, V, transcript);
            }
            // batched_list_polynomial_commitment
            template<
                typename FRI,
                typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<typename FRI::field_type,
                                                                                           typename FRI::lpc_params,
                                                                                           FRI::leaf_size,
                                                                                           false>,
                                                        FRI>::value,
                                        bool>::type = true>
            static bool verify_eval(
                const std::array<std::vector<typename FRI::field_type::value_type>, FRI::leaf_size>
                    &evaluation_points,
                typename FRI::proof_type &proof,
                typename FRI::basic_fri::params_type fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                std::array<std::vector<std::pair<typename FRI::field_type::value_type,
                                                 typename FRI::field_type::value_type>>,
                           FRI::leaf_size>
                    U_interpolation_points;

                for (std::size_t polynom_index = 0; polynom_index < FRI::leaf_size; polynom_index++) {

                    U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());

                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {

                        U_interpolation_points[polynom_index][point_index] = std::make_pair(
                            evaluation_points[polynom_index][point_index], proof.z[polynom_index][point_index]);
                    }
                }

                std::array<math::polynomial<typename FRI::field_type::value_type>, FRI::leaf_size> U;

                for (std::size_t polynom_index = 0; polynom_index < FRI::leaf_size; polynom_index++) {
                    U[polynom_index] = math::lagrange_interpolation(U_interpolation_points[polynom_index]);
                }

                std::array<math::polynomial<typename FRI::field_type::value_type>, FRI::leaf_size> V;

                for (std::size_t polynom_index = 0; polynom_index < FRI::leaf_size; polynom_index++) {
                    V[polynom_index] = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {
                        V[polynom_index] =
                            V[polynom_index] * (math::polynomial<typename FRI::field_type::value_type>(
                                                   {-evaluation_points[polynom_index][point_index], 1}));
                    }
                }

                for (std::size_t round_id = 0; round_id <= FRI::lambda - 1; round_id++) {
                    if (!verify_eval<typename FRI::basic_fri>(
                            proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                        return false;
                    }
                }

                return true;
            }

            template<
                typename FRI,
                typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<typename FRI::field_type,
                                                                                           typename FRI::lpc_params,
                                                                                           FRI::leaf_size,
                                                                                                        false>,
                                                        FRI>::value,
                                        bool>::type = true>
            static bool verify_eval(
                const std::vector<typename FRI::field_type::value_type> &evaluation_points,
                typename FRI::proof_type &proof,
                typename FRI::basic_fri::params_type fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                std::array<std::vector<std::pair<typename FRI::field_type::value_type,
                                                 typename FRI::field_type::value_type>>,
                           FRI::leaf_size>
                    U_interpolation_points;

                for (std::size_t polynom_index = 0; polynom_index < FRI::leaf_size; polynom_index++) {

                    U_interpolation_points[polynom_index].resize(evaluation_points.size());

                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[point_index], proof.z[polynom_index][point_index]);
                    }
                }

                std::array<math::polynomial<typename FRI::field_type::value_type>, FRI::leaf_size> U;

                for (std::size_t polynom_index = 0; polynom_index < FRI::leaf_size; polynom_index++) {
                    U[polynom_index] = math::lagrange_interpolation(U_interpolation_points[polynom_index]);
                }

                math::polynomial<typename FRI::field_type::value_type> V = {1};
                for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                    V = V * (math::polynomial<typename FRI::field_type::value_type>(
                                {-evaluation_points[point_index], 1}));
                }

                for (std::size_t round_id = 0; round_id <= FRI::lambda - 1; round_id++) {
                    if (!typename FRI::basic_fri::verify_eval(
                            proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                        return false;
                    }
                }

                return true;
            }
            // batched_list_polynomial_commitment<FieldType, LPCParams, 0, true>
            template<typename FRI,
                     typename std::enable_if<
                         std::is_base_of<commitments::batched_list_polynomial_commitment<typename FRI::field_type,
                                                                                         typename FRI::lpc_params,
                                                                                         0,
                                                                                         true>,
                                         FRI>::value,
                         bool>::type = true>
            static bool verify_eval(
                const std::vector<std::vector<typename FRI::field_type::value_type>> &evaluation_points,
                typename FRI::proof_type &proof,
                typename FRI::basic_fri::params_type fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                std::size_t leaf_size = proof.z.size();

                std::vector<std::vector<
                    std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>>
                    U_interpolation_points(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());

                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {

                        U_interpolation_points[polynom_index][point_index] = std::make_pair(
                            evaluation_points[polynom_index][point_index], proof.z[polynom_index][point_index]);
                    }
                }

                std::vector<math::polynomial<typename FRI::field_type::value_type>> U(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U[polynom_index] = math::lagrange_interpolation(U_interpolation_points[polynom_index]);
                }

                std::vector<math::polynomial<typename FRI::field_type::value_type>> V(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    V[polynom_index] = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                         point_index++) {
                        V[polynom_index] =
                            V[polynom_index] * (math::polynomial<typename FRI::field_type::value_type>(
                                                   {-evaluation_points[polynom_index][point_index], 1}));
                    }
                }

                for (std::size_t round_id = 0; round_id <= FRI::lambda - 1; round_id++) {
                    if (!verify_eval<typename FRI::basic_fri>(
                            proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                        return false;
                    }
                }

                return true;
            }

            template<typename FRI,
                     typename std::enable_if<
                         std::is_base_of<commitments::batched_list_polynomial_commitment<typename FRI::field_type,
                                                                                         typename FRI::lpc_params,
                                                                                         0,
                                                                                         true>,
                                         FRI>::value,
                         bool>::type = true>
            static bool verify_eval(
                const std::vector<typename FRI::field_type::value_type> &evaluation_points,
                typename FRI::proof_type &proof,
                typename FRI::basic_fri::params_type fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                std::size_t leaf_size = proof.z.size();

                std::vector<std::vector<
                    std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>>
                    U_interpolation_points(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                    U_interpolation_points[polynom_index].resize(evaluation_points.size());

                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {

                        U_interpolation_points[polynom_index][point_index] =
                            std::make_pair(evaluation_points[point_index], proof.z[polynom_index][point_index]);
                    }
                }

                std::vector<math::polynomial<typename FRI::field_type::value_type>> U(leaf_size);

                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                    U[polynom_index] = math::lagrange_interpolation(U_interpolation_points[polynom_index]);
                }

                math::polynomial<typename FRI::field_type::value_type> V = {1};

                for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                    V = V * (math::polynomial<typename FRI::field_type::value_type>(
                                {-evaluation_points[point_index], 1}));
                }

                for (std::size_t round_id = 0; round_id <= FRI::lambda - 1; round_id++) {
                    if (!verify_eval<typename FRI::basic_fri>(
                            proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                        return false;
                    }
                }

                return true;
            }

            // list_polynomial_commitment
            template<
                typename FRI,
                typename std::enable_if<std::is_base_of<
                                                     commitments::list_polynomial_commitment<typename FRI::field_type,
                                                                                typename FRI::lpc_params>, FRI>::value,
                                        bool>::type = true>
            static bool verify_eval(
                const std::vector<typename FRI::field_type::value_type> &evaluation_points,
                typename FRI::proof_type &proof,
                typename FRI::basic_fri::params_type fri_params,
                typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()) {

                std::size_t k = evaluation_points.size();

                std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>
                    U_interpolation_points(k);

                for (std::size_t j = 0; j < k; j++) {
                    U_interpolation_points[j] = std::make_pair(evaluation_points[j], proof.z[j]);
                }

                math::polynomial<typename FRI::field_type::value_type> U =
                    math::lagrange_interpolation(U_interpolation_points);

                math::polynomial<typename FRI::field_type::value_type> V = {1};

                for (std::size_t j = 0; j < k; j++) {
                    V = V * (math::polynomial<typename FRI::field_type::value_type>({-evaluation_points[j], 1}));
                }

                for (std::size_t round_id = 0; round_id <= FRI::lambda - 1; round_id++) {
                    if (!verify_eval<typename FRI::basic_fri>(
                            proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                        return false;
                    }
                }

                return true;
            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ALGORITHMS_VERIFY_EVAL_HPP

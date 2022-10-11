//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                template<typename MerkleTreeHashType, typename TranscriptHashType, std::size_t Lambda = 40,
                         std::size_t R = 1, std::size_t M = 2, std::size_t BatchSize = 0, bool IsConstSize = false>
                struct list_polynomial_commitment_params {
                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t lambda = Lambda;
                    constexpr static const std::size_t r = R;
                    constexpr static const std::size_t m = M;
                    constexpr static const std::size_t leaf_size = BatchSize;
                    constexpr static const bool is_const_size = IsConstSize;
                };
                /**
                 * @brief Based on the FRI Commitment description from \[RedShift].
                 * @tparam d ...
                 * @tparam Rounds Denoted by r in \[Placeholder].
                 *
                 * References:
                 * \[Placeholder]:
                 * "PLACEHOLDER: Transparent SNARKs from List
                 * Polynomial Commitment IOPs",
                 * Assimakis Kattis, Konstantin Panarin, Alexander Vlasov,
                 * Matter Labs,
                 * <https://eprint.iacr.org/2019/1400.pdf>
                 */
                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment;

                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment
                    : public detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                                                       typename LPCParams::transcript_hash_type, LPCParams::m,
                                                       LPCParams::leaf_size, LPCParams::is_const_size> {

                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t r = LPCParams::r;
                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const std::size_t leaf_size = LPCParams::leaf_size;
                    constexpr static const bool is_const_size = LPCParams::is_const_size;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using basic_fri = detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                                                                typename LPCParams::transcript_hash_type, m, leaf_size,
                                                                is_const_size>;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;
                    using field_type = FieldType;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z == rhs.z && fri_proof == rhs.fri_proof && T_root == rhs.T_root;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }
                        typedef typename std::conditional<
                            is_const_size, std::array<std::vector<typename FieldType::value_type>, leaf_size>,
                            std::vector<std::vector<typename FieldType::value_type>>>::type z_type;

                        z_type z;
                        commitment_type T_root;

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;
                    };
                };

                template<typename FieldType, typename LPCParams, std::size_t BatchSize, bool IsConstSize>
                using batched_lpc = batched_list_polynomial_commitment<
                    FieldType, commitments::list_polynomial_commitment_params<
                                   typename LPCParams::merkle_hash_type, typename LPCParams::transcript_hash_type,
                                   LPCParams::lambda, LPCParams::r, LPCParams::m, BatchSize, IsConstSize>>;
                template<typename FieldType, typename LPCParams, std::size_t BatchSize, bool IsConstSize>
                using lpc = batched_list_polynomial_commitment<
                    FieldType, list_polynomial_commitment_params<
                                   typename LPCParams::merkle_hash_type, typename LPCParams::transcript_hash_type,
                                   LPCParams::lambda, LPCParams::r, LPCParams::m, BatchSize, IsConstSize>>;

                template<typename FieldType, typename LPCParams>
                using list_polynomial_commitment = batched_list_polynomial_commitment<FieldType, LPCParams>;

            }    // namespace commitments

            namespace algorithms {
                template<
                    typename LPC,
                    typename ContainerType,    // TODO: check for value_type == std::vector<typename
                                               // LPC::field_type::value_type>?
                    typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                                typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value &&
                                                std::is_same_v<typename ContainerType::value_type,
                                                               std::vector<typename LPC::field_type::value_type>>,
                                            bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const ContainerType &evaluation_points,
                    const typename LPC::precommitment_type &T,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::proof_type::z_type z;

                    typename select_container<LPC::is_const_size,
                                              std::vector<std::pair<typename LPC::field_type::value_type,
                                                                    typename LPC::field_type::value_type>>,
                                              LPC::leaf_size>::type U_interpolation_points;

                    std::size_t leaf_size = g.size();
                    if constexpr (!LPC::is_const_size) {
                        z.resize(leaf_size);
                        U_interpolation_points.resize(leaf_size);
                    }

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        auto evaluation_point = evaluation_points[0];
                        if (polynom_index < evaluation_points.size()) {
                            evaluation_point = evaluation_points[polynom_index];
                        }

                        U_interpolation_points[polynom_index].resize(evaluation_point.size());
                        z[polynom_index].resize(evaluation_point.size());

                        for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {

                            z[polynom_index][point_index] = g[polynom_index].evaluate(
                                evaluation_point[point_index]);    // transform to point-representation

                            U_interpolation_points[polynom_index][point_index] =
                                std::make_pair(evaluation_point[point_index],
                                               z[polynom_index][point_index]);    // prepare points for interpolation
                        }
                    }

                    typename select_container<LPC::is_const_size,
                                              math::polynomial<typename LPC::field_type::value_type>,
                                              LPC::leaf_size>::type Q;
                    if constexpr (!LPC::is_const_size) {
                        Q.resize(leaf_size);
                    }

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                        math::polynomial<typename LPC::field_type::value_type> U =
                            math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                        Q[polynom_index] = (g[polynom_index] - U);
                    }

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        math::polynomial<typename LPC::field_type::value_type> denominator_polynom = {1};
                        auto evaluation_point = evaluation_points[0];
                        if (polynom_index < evaluation_points.size()) {
                            evaluation_point = evaluation_points[polynom_index];
                        }

                        for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {
                            denominator_polynom =
                                denominator_polynom * math::polynomial<typename LPC::field_type::value_type> {
                                                          -evaluation_point[point_index], 1};
                        }
                        Q[polynom_index] = Q[polynom_index] / denominator_polynom;
                    }

                    std::array<typename LPC::basic_fri::proof_type, LPC::lambda> fri_proof;

                    for (std::size_t round_id = 0; round_id <= LPC::lambda - 1; round_id++) {
                        fri_proof[round_id] = proof_eval<typename LPC::basic_fri>(Q, g, T, fri_params, transcript);
                        BOOST_ASSERT(fri_proof[round_id].round_proofs[0].T_root == commit<typename LPC::basic_fri>(T));
                    }

                    return typename LPC::proof_type({z, commit<typename LPC::basic_fri>(T), fri_proof});
                }

                template<
                    typename LPC,
                    typename ContainerType,    // TODO: check for value_type == std::vector<typename
                                               // LPC::field_type::value_type>?
                    typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                                typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value &&
                                                std::is_same_v<typename ContainerType::value_type,
                                                               std::vector<typename LPC::field_type::value_type>>,
                                            bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const ContainerType &evaluation_points,
                    const typename LPC::precommitment_type &T,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial_dfs<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename select_container<LPC::is_const_size,
                                              math::polynomial<typename LPC::field_type::value_type>,
                                              LPC::leaf_size>::type g_normal;
                    if constexpr (!LPC::is_const_size) {
                        g_normal.resize(g.size());
                    }

                    for (int polynom_index = 0; polynom_index < g.size(); ++polynom_index) {
                        g_normal[polynom_index] =
                            math::polynomial<typename LPC::field_type::value_type>(g[polynom_index].coefficients());
                    }

                    return proof_eval<LPC>(evaluation_points, T, g_normal, fri_params, transcript);
                }

                template<
                    typename LPC,
                    typename ContainerType,    // TODO: check for value_type == std::vector<typename
                                               // LPC::field_type::value_type>?
                    typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                                typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value &&
                                                std::is_same_v<typename ContainerType::value_type,
                                                               std::vector<typename LPC::field_type::value_type>>,
                                            bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const ContainerType &evaluation_points,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::precommitment_type T =
                        zk::algorithms::precommit<LPC>(g, fri_params.D.front(), fri_params.step_list.front());
                    return proof_eval<LPC>(evaluation_points, T, g, fri_params, transcript);
                }

                template<
                    typename LPC,
                    typename ContainerType,    // TODO: check for value_type == std::vector<typename
                                               // LPC::field_type::value_type>?
                    typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                                typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value &&
                                                std::is_same_v<typename ContainerType::value_type,
                                                               std::vector<typename LPC::field_type::value_type>>,
                                            bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const ContainerType &evaluation_points,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial_dfs<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::precommitment_type T =
                        zk::algorithms::precommit<LPC>(g, fri_params.D.front(), fri_params.step_list.front());
                    return proof_eval<LPC>(evaluation_points, T, g, fri_params, transcript);
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const typename LPC::precommitment_type &T,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial_dfs<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    std::size_t leaf_size = g.size();
                    typename LPC::proof_type::z_type z;
                    typename select_container<LPC::is_const_size,
                                              std::vector<std::pair<typename LPC::field_type::value_type,
                                                                    typename LPC::field_type::value_type>>,
                                              LPC::leaf_size>::type U_interpolation_points;
                    typename select_container<LPC::is_const_size,
                                              math::polynomial<typename LPC::field_type::value_type>,
                                              LPC::leaf_size>::type g_normal;
                    if constexpr (!LPC::is_const_size) {
                        z.resize(leaf_size);
                        U_interpolation_points.resize(leaf_size);
                        g_normal.resize(leaf_size);
                    }

                    for (int polynom_index = 0; polynom_index < g_normal.size(); ++polynom_index) {
                        g_normal[polynom_index] =
                            math::polynomial<typename LPC::field_type::value_type>(g[polynom_index].coefficients());
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

                    math::polynomial<typename LPC::field_type::value_type> denominator_polynom = {1};
                    for (std::size_t point_index = 0; point_index < evaluation_points.size(); point_index++) {
                        denominator_polynom =
                            denominator_polynom *
                            math::polynomial<typename LPC::field_type::value_type> {-evaluation_points[point_index], 1};
                    }

                    typename select_container<LPC::is_const_size,
                                              math::polynomial<typename LPC::field_type::value_type>,
                                              LPC::leaf_size>::type Q_normal;
                    if constexpr (!LPC::is_const_size) {
                        Q_normal.resize(leaf_size);
                    }
                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                        math::polynomial<typename LPC::field_type::value_type> U =
                            math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                        Q_normal[polynom_index] = (g_normal[polynom_index] - U) / denominator_polynom;
                    }

                    std::array<typename LPC::basic_fri::proof_type, LPC::lambda> fri_proof;

                    typename select_container<LPC::is_const_size,
                                              math::polynomial_dfs<typename LPC::field_type::value_type>,
                                              LPC::leaf_size>::type Q;
                    if constexpr (!LPC::is_const_size) {
                        Q.resize(leaf_size);
                    }

                    for (int polynom_index = 0; polynom_index < Q_normal.size(); ++polynom_index) {
                        Q[polynom_index].from_coefficients(Q_normal[polynom_index]);
                        Q[polynom_index].resize(fri_params.D[0]->size());
                    }

                    for (std::size_t round_id = 0; round_id <= LPC::lambda - 1; round_id++) {
                        fri_proof[round_id] = proof_eval<typename LPC::basic_fri>(Q, g, T, fri_params, transcript);
                        BOOST_ASSERT(fri_proof[round_id].round_proofs[0].T_root == commit<typename LPC::basic_fri>(T));
                    }

                    return typename LPC::proof_type({z, commit<typename LPC::basic_fri>(T), fri_proof});
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const typename LPC::precommitment_type &T,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {
                    std::array<std::vector<typename LPC::field_type::value_type>, 1> tmp = {evaluation_points};
                    return proof_eval<LPC>(tmp, T, g, fri_params, transcript);
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial_dfs<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,

                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::precommitment_type T =
                        zk::algorithms::precommit<LPC>(g, fri_params.D.front(), fri_params.step_list.front());
                    return proof_eval<LPC>(evaluation_points, g, T, fri_params, transcript);
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const typename select_container<LPC::is_const_size,
                                                    math::polynomial<typename LPC::field_type::value_type>,
                                                    LPC::leaf_size>::type &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::precommitment_type T =
                        zk::algorithms::precommit<LPC>(g, fri_params.D.front(), fri_params.step_list.front());
                    return proof_eval<LPC>(evaluation_points, g, T, fri_params, transcript);
                }

                template<
                    typename LPC, typename ContainerType,
                    typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                                typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value &&
                                                std::is_same_v<typename ContainerType::value_type,
                                                               std::vector<typename LPC::field_type::value_type>>,
                                            bool>::type = true>
                static bool verify_eval(
                    const ContainerType &evaluation_points,
                    typename LPC::proof_type &proof,
                    const typename LPC::commitment_type &t_polynomials,
                    typename LPC::basic_fri::params_type fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    if (t_polynomials != proof.T_root)
                        return false;

                    std::size_t leaf_size = proof.z.size();
                    std::size_t eval_size = evaluation_points.size();

                    typename select_container<LPC::is_const_size,
                                              std::vector<std::pair<typename LPC::field_type::value_type,
                                                                    typename LPC::field_type::value_type>>,
                                              LPC::leaf_size>::type U_interpolation_points;

                    if constexpr (!LPC::is_const_size) {
                        U_interpolation_points.resize(leaf_size);
                    }

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        auto evaluation_point = evaluation_points[0];
                        if (polynom_index < eval_size) {
                            evaluation_point = evaluation_points[polynom_index];
                        }

                        U_interpolation_points[polynom_index].resize(evaluation_point.size());

                        for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {

                            U_interpolation_points[polynom_index][point_index] =
                                std::make_pair(evaluation_point[point_index], proof.z[polynom_index][point_index]);
                        }
                    }

                    typename select_container<LPC::is_const_size,
                                              math::polynomial<typename LPC::field_type::value_type>,
                                              LPC::leaf_size>::type U,
                        V;

                    if constexpr (!LPC::is_const_size) {
                        U.resize(leaf_size);
                        V.resize(leaf_size);
                    }

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                        U[polynom_index] = math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                        V[polynom_index] = {1};
                        auto evaluation_point = evaluation_points[0];
                        if (polynom_index < eval_size) {
                            evaluation_point = evaluation_points[polynom_index];
                        }

                        for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {
                            V[polynom_index] =
                                V[polynom_index] * (math::polynomial<typename LPC::field_type::value_type>(
                                                       {-evaluation_point[point_index], 1}));
                        }
                    }

                    for (std::size_t round_id = 0; round_id <= LPC::lambda - 1; round_id++) {
                        if (!verify_eval<typename LPC::basic_fri>(proof.fri_proof[round_id], fri_params, t_polynomials,
                                                                  U, V, transcript)) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static bool verify_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    typename LPC::proof_type &proof,
                    typename LPC::commitment_type t_polynomials,
                    typename LPC::basic_fri::params_type fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    std::array<std::vector<typename LPC::field_type::value_type>, 1> tmp;
                    tmp[0] = evaluation_points;
                    return verify_eval<LPC>(tmp, proof, t_polynomials, fri_params, transcript);
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const typename LPC::precommitment_type &T,
                    const math::polynomial<typename LPC::field_type::value_type> &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    std::size_t k = evaluation_points.size();
                    typename LPC::proof_type::z_type z;
                    // TODO: z[0] - not so good decision. Maybe using another proof_eval for this case?
                    z.resize(1);
                    z[0].resize(k);
                    //                    std::vector<typename LPC::field_type::value_type> z(k);
                    std::vector<std::pair<typename LPC::field_type::value_type, typename LPC::field_type::value_type>>
                        U_interpolation_points(k);

                    for (std::size_t j = 0; j < k; j++) {
                        z[0][j] = g.evaluate(evaluation_points[j]);    // transform to point-representation
                        U_interpolation_points[j] =
                            std::make_pair(evaluation_points[j], z[0][j]);    // prepare points for interpolation
                    }

                    math::polynomial<typename LPC::field_type::value_type> U =
                        math::lagrange_interpolation(U_interpolation_points);    // k is small => iterpolation goes fast

                    math::polynomial<typename LPC::field_type::value_type> Q = (g - U);
                    for (std::size_t j = 0; j < k; j++) {
                        math::polynomial<typename LPC::field_type::value_type> denominator_polynom = {
                            -evaluation_points[j], 1};
                        Q = Q / denominator_polynom;
                    }

                    std::array<typename LPC::basic_fri::proof_type, LPC::lambda> fri_proof;

                    for (std::size_t round_id = 0; round_id <= LPC::lambda - 1; round_id++) {
                        fri_proof[round_id] = proof_eval<typename LPC::basic_fri>(Q, g, T, fri_params, transcript);
                        BOOST_ASSERT(fri_proof[round_id].round_proofs[0].T_root == commit<typename LPC::basic_fri>(T));
                    }

                    return typename LPC::proof_type({z, commit<typename LPC::basic_fri>(T), fri_proof});
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const typename LPC::precommitment_type &T,
                    const math::polynomial_dfs<typename LPC::field_type::value_type> &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    math::polynomial<typename LPC::field_type::value_type> g_normal(g.coefficients());

                    return proof_eval<LPC>(evaluation_points, T, g_normal, fri_params, transcript);
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const math::polynomial<typename LPC::field_type::value_type> &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::precommitment_type T =
                        zk::algorithms::precommit<LPC>(g, fri_params.D.front(), fri_params.step_list.front());
                    return proof_eval<LPC>(evaluation_points, T, g, fri_params, transcript);
                }

                template<typename LPC, typename std::enable_if<
                                           std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                               typename LPC::field_type, typename LPC::lpc_params>,
                                                           LPC>::value,
                                           bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::vector<typename LPC::field_type::value_type> &evaluation_points,
                    const math::polynomial_dfs<typename LPC::field_type::value_type> &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()) {

                    typename LPC::precommitment_type T =
                        zk::algorithms::precommit<LPC>(g, fri_params.D.front(), fri_params.step_list.front());
                    return proof_eval<LPC>(evaluation_points, T, g, fri_params, transcript);
                }
            }    // namespace algorithms
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

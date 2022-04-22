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

#ifndef CRYPTO3_ZK_BATCHED_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_BATCHED_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                /**
                 * @brief Based on the FRI Commitment description from \[ResShift].
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
                template<typename FieldType, typename LPCParams, std::size_t BatchSize = 1>
                struct batched_list_polynomial_commitment
                    : public detail::basic_batched_fri<FieldType,
                                                       typename LPCParams::merkle_hash_type,
                                                       typename LPCParams::transcript_hash_type,
                                                       LPCParams::m,
                                                       BatchSize> {

                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t r = LPCParams::r;
                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const std::size_t leaf_size = BatchSize;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using fri_type = batched_fri<FieldType,
                                                 typename LPCParams::merkle_hash_type,
                                                 typename LPCParams::transcript_hash_type,
                                                 m,
                                                 leaf_size>;
                    using basic_fri = typename fri_type::basic_fri;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z == rhs.z && fri_proof == rhs.fri_proof && T_root == rhs.T_root;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        std::array<std::vector<typename FieldType::value_type>, leaf_size> z;

                        commitment_type T_root;

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;
                    };

                    static proof_type proof_eval(
                        const std::array<std::vector<typename FieldType::value_type>, leaf_size> &evaluation_points,
                        precommitment_type &T,
                        const std::array<math::polynomial<typename FieldType::value_type>, leaf_size> &g,
                        const typename basic_fri::params_type &fri_params,
                        typename basic_fri::transcript_type &transcript = typename basic_fri::transcript_type()) {

                        std::array<std::vector<typename FieldType::value_type>, leaf_size> z;
                        std::array<
                            std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>>,
                            leaf_size>
                            U_interpolation_points;

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());
                            z[polynom_index].resize(evaluation_points[polynom_index].size());

                            for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                                 point_index++) {

                                z[polynom_index][point_index] = g[polynom_index].evaluate(
                                    evaluation_points[polynom_index]
                                                     [point_index]);    // transform to point-representation

                                U_interpolation_points[polynom_index][point_index] = std::make_pair(
                                    evaluation_points[polynom_index][point_index],
                                    z[polynom_index][point_index]);    // prepare points for interpolation
                            }
                        }

                        std::array<math::polynomial<typename FieldType::value_type>, leaf_size> Q;
                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                            math::polynomial<typename FieldType::value_type> U =
                                math::lagrange_interpolation(U_interpolation_points[polynom_index]);

                            Q[polynom_index] = (g[polynom_index] - U);
                        }

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            math::polynomial<typename FieldType::value_type> denominator_polynom = {1};
                            for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                                 point_index++) {
                                denominator_polynom =
                                    denominator_polynom * math::polynomial<typename FieldType::value_type> {
                                                              -evaluation_points[polynom_index][point_index], 1};
                            }
                            Q[polynom_index] = Q[polynom_index] / denominator_polynom;
                        }

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;

                        for (std::size_t round_id = 0; round_id <= lambda - 1; round_id++) {
                            fri_proof[round_id] = basic_fri::proof_eval(Q, g, T, fri_params, transcript);
                        }

                        return proof_type({z, basic_fri::commit(T), fri_proof});
                    }

                    static bool verify_eval(
                        const std::array<std::vector<typename FieldType::value_type>, leaf_size> &evaluation_points,
                        proof_type &proof,
                        typename basic_fri::params_type fri_params,
                        typename basic_fri::transcript_type &transcript = typename basic_fri::transcript_type()) {

                        std::array<
                            std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>>,
                            leaf_size>
                            U_interpolation_points;

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                            U_interpolation_points[polynom_index].resize(evaluation_points[polynom_index].size());

                            for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                                 point_index++) {

                                U_interpolation_points[polynom_index][point_index] = std::make_pair(
                                    evaluation_points[polynom_index][point_index], proof.z[polynom_index][point_index]);
                            }
                        }

                        std::array<math::polynomial<typename FieldType::value_type>, leaf_size> U;

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            U[polynom_index] = math::lagrange_interpolation(U_interpolation_points[polynom_index]);
                        }

                        std::array<math::polynomial<typename FieldType::value_type>, leaf_size> V;

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            V[polynom_index] = {1};
                            for (std::size_t point_index = 0; point_index < evaluation_points[polynom_index].size();
                                 point_index++) {
                                V[polynom_index] =
                                    V[polynom_index] * (math::polynomial<typename FieldType::value_type>(
                                                           {-evaluation_points[polynom_index][point_index], 1}));
                            }
                        }

                        for (std::size_t round_id = 0; round_id <= lambda - 1; round_id++) {
                            if (!basic_fri::verify_eval(proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                                return false;
                            }
                        }

                        return true;
                    }
                };

                template<typename FieldType, typename LPCParams, std::size_t BatchSize = 1>
                using batched_lpc = batched_list_polynomial_commitment<FieldType, LPCParams, BatchSize>;
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BATCHED_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

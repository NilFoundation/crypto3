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
                template<typename MerkleTreeHashType,
                         typename TranscriptHashType,
                         std::size_t Lambda = 40,
                         std::size_t R = 1,
                         std::size_t M = 2>
                struct list_polynomial_commitment_params {
                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t lambda = Lambda;
                    constexpr static const std::size_t r = R;
                    constexpr static const std::size_t m = M;
                };

                /**
                 * @brief Based on the FRI Commitment description from \[ResShift].
                 * @tparam d ...
                 * @tparam Rounds Denoted by r in \[RedShift].
                 *
                 * References:
                 * \[RedShift]:
                 * "REDSHIFT: Transparent SNARKs from List
                 * Polynomial Commitment IOPs",
                 * Assimakis Kattis, Konstantin Panarin, Alexander Vlasov,
                 * Matter Labs,
                 * <https://eprint.iacr.org/2019/1400.pdf>
                 */
                template<typename FieldType, typename LPCParams, std::size_t K = 1>
                struct list_polynomial_commitment : public detail::basic_fri<FieldType,
                                                                             typename LPCParams::merkle_hash_type,
                                                                             typename LPCParams::transcript_hash_type,
                                                                             LPCParams::m> {

                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t r = LPCParams::r;
                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const std::size_t k = K;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using basic_fri = detail::basic_fri<FieldType,
                                                        typename LPCParams::merkle_hash_type,
                                                        typename LPCParams::transcript_hash_type,
                                                        m>;
                    using fri_type = fri<FieldType,
                                         typename LPCParams::merkle_hash_type,
                                         typename LPCParams::transcript_hash_type,
                                         m>;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z == rhs.z && fri_proof == rhs.fri_proof && T_root == rhs.T_root;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        std::array<typename FieldType::value_type, k> z;

                        commitment_type T_root;

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;
                    };

                    static proof_type proof_eval(
                        const std::array<typename FieldType::value_type, k> &evaluation_points,
                        precommitment_type &T,
                        const math::polynomial<typename FieldType::value_type> &g,
                        const typename basic_fri::params_type &fri_params,
                        typename basic_fri::transcript_type &transcript = typename basic_fri::transcript_type()) {

                        std::array<typename FieldType::value_type, k> z;
                        std::array<merkle_proof_type, k> p;
                        std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, k>
                            U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++) {
                            z[j] = g.evaluate(evaluation_points[j]);    // transform to point-representation
                            U_interpolation_points[j] =
                                std::make_pair(evaluation_points[j], z[j]);    // prepare points for interpolation
                        }

                        math::polynomial<typename FieldType::value_type> U = math::lagrange_interpolation(
                            U_interpolation_points);    // k is small => iterpolation goes fast

                        math::polynomial<typename FieldType::value_type> Q = (g - U);
                        for (std::size_t j = 0; j < k; j++) {
                            math::polynomial<typename FieldType::value_type> denominator_polynom = {
                                -evaluation_points[j], 1};
                            Q = Q / denominator_polynom;    // polynomial divison
                        }

                        // temporary definition, until polynomial is constexpr
                        const math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;

                        for (std::size_t round_id = 0; round_id <= lambda - 1; round_id++) {
                            fri_proof[round_id] = basic_fri::proof_eval(Q, g, T, fri_params, transcript);
                        }

                        return proof_type({z, basic_fri::commit(T), fri_proof});
                    }

                    static bool verify_eval(
                        const std::array<typename FieldType::value_type, k> &evaluation_points,
                        proof_type &proof,
                        typename basic_fri::params_type fri_params,
                        typename basic_fri::transcript_type &transcript = typename basic_fri::transcript_type()) {

                        std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, k>
                            U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++) {
                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], proof.z[j]);
                        }

                        math::polynomial<typename FieldType::value_type> U =
                            math::lagrange_interpolation(U_interpolation_points);

                        math::polynomial<typename FieldType::value_type> V = {1};

                        for (std::size_t j = 0; j < k; j++) {
                            V = V * (math::polynomial<typename FieldType::value_type>({-evaluation_points[j], 1}));
                        }

                        for (std::size_t round_id = 0; round_id <= lambda - 1; round_id++) {
                            if (!basic_fri::verify_eval(proof.fri_proof[round_id], fri_params, U, V, transcript)) {
                                return false;
                            }
                        }

                        return true;
                    }
                };

                template<typename FieldType, typename LPCParams, std::size_t K>
                using lpc = list_polynomial_commitment<FieldType, LPCParams, K>;
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

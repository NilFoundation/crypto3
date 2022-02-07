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

#ifndef CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/merkle/tree.hpp>
#include <nil/crypto3/merkle/proof.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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
                template<typename FieldType,
                         typename Hash,
                         std::size_t Lambda = 40,
                         std::size_t K = 1,
                         std::size_t R = 1,
                         std::size_t M = 2,
                         std::size_t D = 16>
                struct list_polynomial_commitment_scheme {
                    using Endianness = nil::marshalling::option::big_endian;
                    using field_element_type =
                            nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<Endianness>,
                                                                            FieldType>;

                    constexpr static const std::size_t lambda = Lambda;
                    constexpr static const std::size_t k = K;
                    constexpr static const std::size_t r = R;
                    constexpr static const std::size_t m = M;

                    typedef FieldType field_type;
                    typedef Hash transcript_hash_type;

                    typedef typename containers::merkle_tree<Hash, 2> merkle_tree_type;
                    typedef typename merkle_tree_type::hash_type merkle_hash_type;
                    typedef typename containers::merkle_proof<Hash, 2> merkle_proof_type;

                    typedef fri_commitment_scheme<FieldType, Hash, m> fri_type;

                    using commitment_type = typename merkle_tree_type::value_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z == rhs.z && fri_proof == rhs.fri_proof;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        std::array<typename FieldType::value_type, k> z;

                        typename merkle_tree_type::value_type T_root;

                        std::array<typename fri_type::proof_type, lambda> fri_proof;
                    };

                private:
                    static std::shared_ptr<math::evaluation_domain<FieldType>> prepare_domain(const std::size_t domain_size) {
                        return math::make_evaluation_domain<FieldType>(domain_size);
                    }

                public:
                    // The result of this function is not commitment_type (as it would expected),
                    // but the built Merkle tree. This is done so, because we often need to reuse
                    // the built Merkle tree
                    // After this function
                    // result.root();
                    // should be called
                    static merkle_tree_type
                        commit(math::polynomial::polynomial<typename FieldType::value_type> &f,
                               const std::shared_ptr<math::evaluation_domain<FieldType>> &d) {

                        return fri_type::commit(f, d);
                    }

                    static proof_type proof_eval(const std::array<typename FieldType::value_type, k> &evaluation_points,
                                                 merkle_tree_type &T,
                                                 const math::polynomial::polynomial<typename FieldType::value_type> &g,
                                                 fiat_shamir_heuristic_updated<transcript_hash_type> &transcript,
                                                 typename fri_type::params_type &fri_params) {

                        std::array<typename FieldType::value_type, k> z;
                        std::array<merkle_proof_type, k> p;
                        std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, k>
                            U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++) {
                            z[j] = g.evaluate(evaluation_points[j]);
                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], z[j]);
                        }

                        math::polynomial::polynomial<typename FieldType::value_type> U =
                            math::polynomial::lagrange_interpolation(U_interpolation_points);

                        math::polynomial::polynomial<typename FieldType::value_type> Q = (g - U);
                        for (std::size_t j = 0; j < k; j++) {
                            math::polynomial::polynomial<typename FieldType::value_type> denominator_polynom = {
                                -evaluation_points[j], 1};
                            Q = Q / denominator_polynom;
                        }

                        // temporary definition, until polynomial is constexpr
                        const math::polynomial::polynomial<typename FieldType::value_type> q = {0, 0, 1};

                        std::array<typename fri_type::proof_type, lambda> fri_proof;

                        for (std::size_t round_id = 0; round_id <= lambda - 1; round_id++) {
                            fri_proof[round_id] = fri_type::proof_eval(Q, g, T, transcript, fri_params);
                        }

                        return proof_type({z, T.root(), fri_proof});
                    }

                    static bool verify_eval(const std::array<typename FieldType::value_type, k> &evaluation_points,
                                            proof_type &proof,
                                            fiat_shamir_heuristic_updated<transcript_hash_type> &transcript,
                                            typename fri_type::params_type fri_params) {
                        std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, k>
                            U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++) {
                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], proof.z[j]);
                        }

                        math::polynomial::polynomial<typename FieldType::value_type> U =
                            math::polynomial::lagrange_interpolation(U_interpolation_points);

                        math::polynomial::polynomial<typename FieldType::value_type> V = {1};

                        for (std::size_t j = 0; j < k; j++) {
                            V = V * (math::polynomial::polynomial<typename FieldType::value_type>({-evaluation_points[j], 1}));
                        }

                        for (std::size_t round_id = 0; round_id <= lambda - 1; round_id++) {
                            if (!fri_type::verify_eval(proof.fri_proof[round_id], transcript, fri_params, U, V)) {
                                return false;
                            }
                        }

                        return true;

                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

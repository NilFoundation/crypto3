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
                    constexpr static const std::size_t lambda = Lambda;
                    constexpr static const std::size_t k = K;
                    constexpr static const std::size_t r = R;
                    constexpr static const std::size_t m = M;

                    typedef FieldType field_type;
                    typedef Hash transcript_hash_type;

                    typedef typename containers::merkle_tree<Hash, 2> merkle_tree_type;
                    typedef typename merkle_tree_type::hash_type merkle_hash_type;
                    typedef std::vector<typename merkle_tree_type::value_type> merkle_proof_type;

                    typedef fri_commitment_scheme<FieldType, merkle_hash_type, m> fri_type;

                    struct transcript_round_manifest {
                        enum challenges_ids { x, y };
                    };

                    using openning_type = merkle_proof_type;
                    using commitment_type = typename merkle_tree_type::value_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z_openings == rhs.z_openings && alpha_openings == rhs.alpha_openings &&
                                   f_y_openings == rhs.f_y_openings && f_commitments == rhs.f_commitments &&
                                   f_ip1_coefficients == rhs.f_ip1_coefficients;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        std::array<merkle_proof_type, k> z_openings;

                        std::array<std::array<commitment_type, r - 1>, lambda> f_commitments;

                        std::array<math::polynomial::polynomial<typename FieldType::value_type>, lambda>
                            f_ip1_coefficients;
                    };

                private:
                    std::vector<typename FieldType::value_type> prepare_domain(const std::size_t domain_size) {
                        typename FieldType::value_type omega =
                            math::unity_root<FieldType>(math::detail::get_power_of_two(domain_size));
                        std::vector<typename FieldType::value_type> d(domain_size);
                        for (std::size_t power = 1; power <= domain_size; power++) {
                            d.emplace_back(omega.pow(power));
                        }
                        return d;
                    }

                public:
                    // The result of this function is not commitment_type (as it would expected),
                    // but the built Merkle tree. This is done so, because we often need to reuse
                    // the built Merkle tree
                    // After this function
                    // result.root();
                    // should be called
                    static merkle_tree_type
                        commit(const math::polynomial::polynomial<typename FieldType::value_type> &f,
                               const std::vector<typename FieldType::value_type> &d) {

                        return fri_type::commit(f, d);
                    }

                    static proof_type proof_eval(const std::array<typename FieldType::value_type, k> &evaluation_points,
                                                 const merkle_tree_type &T,
                                                 const math::polynomial::polynomial<typename FieldType::value_type> &g,
                                                 fiat_shamir_heuristic_updated<transcript_hash_type> &transcript) {

                        proof_type proof;

                        fiat_shamir_heuristic<transcript_round_manifest, transcript_hash_type> transcript;

                        std::array<merkle_proof_type, k> &z_openings = proof.z_openings;
                        std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, k>
                            U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++) {
                            typename FieldType::value_type z_j = g.evaluate(evaluation_points[j]);
                            std::size_t leaf_index = std::find(D.begin(), D.end(), evaluation_points[j]) - D.begin();
                            z_openings[j] = merkle_proof_type(T, leaf_index);
                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], z_j);
                        }

                        math::polynomial::polynomial<typename FieldType::value_type> U =
                            math::polynomial::lagrange_interpolation(U_interpolation_points);

                        math::polynomial::polynomial<typename FieldType::value_type> Q = (g - U);
                        for (std::size_t j = 0; j < k; j++) {
                            math::polynomial::polynomial<typename FieldType::value_type> denominator_polynom = {
                                -evaluation_points[j], 1};
                            Q = Q / denominator_polynom;
                        }

                        std::vector<std::vector<typename FieldType::value_type>> D;
                        std::size_t d = D;
                        for (std::size_t j = 0; j <= r - 1; j++) {
                            D[j] = prepare_domain(d / 2);
                        }

                        // temporary definition, until polynomial is constexpr
                        const math::polynomial::polynomial<typename FieldType::value_type> q = {0, 0, 1};

                        fri_type::params_type fri_params = {r, D, q};

                        for (std::size_t round_id = 0; round_id < lambda; round_id++) {
                        }

                        return proof;
                    }

                    static bool verify_eval(const std::array<typename FieldType::value_type, k> &evaluation_points,
                                            const commitment_type &root,
                                            const proof_type &proof,
                                            const std::vector<typename FieldType::value_type> &d) {
                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

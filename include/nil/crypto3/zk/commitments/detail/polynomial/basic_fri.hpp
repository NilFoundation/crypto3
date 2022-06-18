//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP
#define CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>

//#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
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
                    template<typename FieldType,
                             typename MerkleTreeHashType,
                             typename TranscriptHashType,
                             std::size_t M, std::size_t BatchSize>
                    struct basic_batched_fri {

                        constexpr static const std::size_t m = M;
                        constexpr static const std::size_t leaf_size = BatchSize;

                        typedef FieldType field_type;
                        typedef MerkleTreeHashType merkle_tree_hash_type;
                        typedef TranscriptHashType transcript_hash_type;

                        typedef typename containers::merkle_tree<MerkleTreeHashType, 2> merkle_tree_type;
                        typedef typename containers::merkle_proof<MerkleTreeHashType, 2> merkle_proof_type;

                        using Endianness = nil::marshalling::option::big_endian;
                        using field_element_type =
                            nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<Endianness>,
                                                                            typename FieldType::value_type>;

                        using precommitment_type = merkle_tree_type;
                        using commitment_type = typename precommitment_type::value_type;
                        using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;

                        struct params_type {
                            bool operator==(const params_type &rhs) const {
                                return r == rhs.r && max_degree == rhs.max_degree && D == rhs.D;
                            }
                            bool operator!=(const params_type &rhs) const {
                                return !(rhs == *this);
                            }

                            std::size_t r;
                            std::size_t max_degree;
                            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;
                        };

                        struct round_proof_type {
                            // bool operator==(const round_proof_type &rhs) const {
                            //     return y == rhs.y && p == rhs.p && T_root == rhs.T_root &&
                            //            colinear_value == rhs.colinear_value && colinear_path == rhs.colinear_path;
                            // }
                            // bool operator!=(const round_proof_type &rhs) const {
                            //     return !(rhs == *this);
                            // }
                            typename std::conditional<leaf_size == 1, std::array<std::array<typename FieldType::value_type, m>, 1>, std::vector<std::array<typename FieldType::value_type, m>>>::type y;
//                            std::array<typename FieldType::value_type, m> y;
                            std::array<merkle_proof_type, m> p;

                            typename merkle_tree_type::value_type T_root;

                            typename std::conditional<leaf_size == 1, std::array<typename FieldType::value_type, 1>, std::vector<typename FieldType::value_type>>::type colinear_value;

//                            typename FieldType::value_type colinear_value;
                            merkle_proof_type colinear_path;
                        };

                        struct proof_type {
                            bool operator==(const proof_type &rhs) const {
                                return round_proofs == rhs.round_proofs && final_polynomials == rhs.final_polynomials &&
                                       target_commitment == rhs.target_commitment;
                            }
                            bool operator!=(const proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            std::vector<round_proof_type> round_proofs;    // 0..r-2

                            typename std::conditional<leaf_size == 1,  std::array<math::polynomial<typename FieldType::value_type>, 1>, std::vector<math::polynomial<typename FieldType::value_type>>>::type final_polynomials;
//                            typename std::conditional<leaf_size == 1,  math::polynomial<typename FieldType::value_type>, math::polynomial<typename FieldType::value_type>>::type final_polynomial;
//                            math::polynomial<typename FieldType::value_type> final_polynomial;
                            commitment_type target_commitment;
                        };
                    };
                }    // namespace detail
            }        // namespace commitments

            namespace algorithms {
                template<
                    typename FRI,
                    typename std::enable_if<
                        std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                       typename FRI::merkle_tree_hash_type,
                                                                       typename FRI::transcript_hash_type,
                                                                       FRI::m, 1>,
                                        FRI>::value ||
                            std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                   typename FRI::merkle_tree_hash_type,
                                                                                   typename FRI::transcript_hash_type,
                                                                                   FRI::m, 0>,
                                            FRI>::value,
                        bool>::type = true>
                static typename FRI::commitment_type commit(typename FRI::precommitment_type P) {
                    return P.root();
                }

                template<typename FRI,
                         std::size_t list_size,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                            typename FRI::merkle_tree_hash_type,
                                                                            typename FRI::transcript_hash_type,
                                                                            FRI::m, 1>,
                                             FRI>::value,
                             bool>::type = true>
                static std::array<typename FRI::commitment_type, list_size>
                    commit(std::array<typename FRI::precommitment_type, list_size> P) {

                    std::array<typename FRI::commitment_type, list_size> commits;
                    for (std::size_t i = 0; i < list_size; i++) {
                        commits[i] = commit(P);
                    }
                    return commits;
                }

                template<typename FRI,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                            typename FRI::merkle_tree_hash_type,
                                                                            typename FRI::transcript_hash_type,
                                                                            FRI::m, 1>,
                                             FRI>::value,
                             bool>::type = true>
                static typename FRI::precommitment_type
                    precommit(math::polynomial_dfs<typename FRI::field_type::value_type> f,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                    if (f.size() != D->size()) {
                        f.resize(D->size());
                    }
                    std::vector<std::array<std::uint8_t, FRI::field_element_type::length()>> y_data;
                    y_data.resize(D->size());

                    for (std::size_t i = 0; i < D->size(); i++) {
                        typename FRI::field_element_type y_val(f[i]);
                        auto write_iter = y_data[i].begin();
                        y_val.write(write_iter, FRI::field_element_type::length());
                    }

                    return containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, FRI::m>(y_data.begin(),
                                                                                                     y_data.end());
                }

                template<typename FRI,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                            typename FRI::merkle_tree_hash_type,
                                                                            typename FRI::transcript_hash_type,
                                                                            FRI::m, 1>,
                                             FRI>::value,
                             bool>::type = true>
                static typename FRI::precommitment_type
                    precommit(const math::polynomial<typename FRI::field_type::value_type> &f,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                    math::polynomial_dfs<typename FRI::field_type::value_type> f_dfs;
                    f_dfs.from_coefficients(f);

                    return precommit<FRI>(f_dfs, D);
                }

                template<typename FRI,
                         std::size_t list_size,
                         typename PolynomialType,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                            typename FRI::merkle_tree_hash_type,
                                                                            typename FRI::transcript_hash_type,
                                                                            FRI::m, 1>,
                                             FRI>::value,
                             bool>::type = true>
                static std::array<typename FRI::precommitment_type, list_size>
                    precommit(const std::array<PolynomialType, list_size> &poly,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &domain) {
                    std::array<typename FRI::precommitment_type, list_size> precommits;
                    for (std::size_t i = 0; i < list_size; i++) {
                        precommits[i] = precommit(poly[i], domain);
                    }
                    return precommits;
                }

                template<typename FRI, typename PolynomType,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                            typename FRI::merkle_tree_hash_type,
                                                                            typename FRI::transcript_hash_type,
                                                                            FRI::m, 1>,
                                             FRI>::value,
                             bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(PolynomType f,
                               const PolynomType &g,
                               typename FRI::precommitment_type &T,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    transcript(commit<FRI>(T));

                    // TODO: how to sample x?
                    std::size_t domain_size = fri_params.D[0]->size();
                    if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                 PolynomType>) {
                        f.resize(domain_size);
                    }
                    std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) %
                    domain_size;

                    typename FRI::field_type::value_type x =
                                            fri_params.D[0]->get_domain_element(x_index);

                    std::size_t r = fri_params.r;

                    std::vector<typename FRI::round_proof_type> round_proofs;
                    std::unique_ptr<typename FRI::merkle_tree_type> p_tree =
                        std::make_unique<typename FRI::merkle_tree_type>(T);
                    typename FRI::merkle_tree_type T_next;

                    for (std::size_t i = 0; i < r - 1; i++) {

                        std::size_t domain_size = fri_params.D[i]->size();

                        typename FRI::field_type::value_type alpha =
                            transcript.template challenge<typename FRI::field_type>();

                        x_index %= domain_size;

                        // m = 2, so:
                        std::array<typename FRI::field_type::value_type, FRI::m> s;
                        std::array<std::size_t, FRI::m> s_indices;
                        if constexpr (FRI::m == 2) {
                            s[0] = x;
                            s[1] = -x;
                            s_indices[0] = x_index;
                            s_indices[1] = (x_index + domain_size / 2) % domain_size;
                        } else {
                            return {};
                        }

                        std::array<typename FRI::field_type::value_type, FRI::m> y;
                        std::array<typename FRI::merkle_proof_type, FRI::m> p;

                        for (std::size_t j = 0; j < FRI::m; j++) {
                            if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                         PolynomType>) {
                                y[j] = (i == 0 ? g[s_indices[j]] : f[s_indices[j]]);
                            } else {
                                y[j] = (i == 0 ? g.evaluate(s[j]) : f.evaluate(s[j]));
                            }
                            p[j] = typename FRI::merkle_proof_type(*p_tree, s_indices[j]);
                        }

                        x_index %= fri_params.D[i + 1]->size();
                        x = fri_params.D[i + 1]->get_domain_element(x_index);

                        typename FRI::field_type::value_type colinear_value;
                        // create polynomial of degree (degree(f) / 2)
                        if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                     PolynomType>) {
                            if (i == 0) {
                                f.resize(fri_params.D[i]->size());
                            }
                            f = commitments::detail::fold_polynomial<typename FRI::field_type>(f, alpha,
                                                                                               fri_params.D[i]);
                            colinear_value = f[x_index];
                        } else {
                            f = commitments::detail::fold_polynomial<typename FRI::field_type>(f, alpha);
                            colinear_value = f.evaluate(x);
                        }

                        T_next = precommit<FRI>(f, fri_params.D[i + 1]);    // new merkle tree
                        transcript(commit<FRI>(T_next));

                        typename FRI::merkle_proof_type colinear_path = typename
                        FRI::merkle_proof_type(T_next, x_index);

                        round_proofs.push_back(
                            typename FRI::round_proof_type({y, p, p_tree->root(), colinear_value,
                            colinear_path}));

                        p_tree = std::make_unique<typename FRI::merkle_tree_type>(T_next);
                    }

                    if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                 PolynomType>) {
                        math::polynomial<typename FRI::field_type::value_type> f_normal(f.coefficients());
                        return typename FRI::proof_type({round_proofs, f_normal, commit<FRI>(T)});
                    } else {
                        return typename FRI::proof_type({round_proofs, f, commit<FRI>(T)});
                    }
                    return {};
                }

                template<typename FRI,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                            typename FRI::merkle_tree_hash_type,
                                                                            typename FRI::transcript_hash_type,
                                                                            FRI::m, 1>,
                                             FRI>::value,
                             bool>::type = true>
                static bool verify_eval(typename FRI::proof_type &proof,
                                        typename FRI::params_type &fri_params,
                                        const math::polynomial<typename FRI::field_type::value_type> &U,
                                        const math::polynomial<typename FRI::field_type::value_type> &V,
                                        typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {

                    transcript(proof.target_commitment);

                    std::size_t domain_size = fri_params.D[0]->size();
                    std::uint64_t x_index = transcript.template int_challenge<std::uint64_t>() % domain_size;
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
                            std::array<std::uint8_t, FRI::field_element_type::length()> leaf_data;
// zerg_remove
                            typename FRI::field_type::value_type leaf = proof.round_proofs[i].y[0][j];

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
                                // zerg_remove
                                y[j] = (proof.round_proofs[i].y[0][j] - U.evaluate(s[j])) / V.evaluate(s[j]);
                            } else {
                                y[j] = proof.round_proofs[i].y[0][j];
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

                        typename FRI::field_type::value_type leaf = proof.round_proofs[i].colinear_value[0];

                        std::array<std::uint8_t, FRI::field_element_type::length()> leaf_data;
                        typename FRI::field_element_type leaf_val(leaf);
                        auto write_iter = leaf_data.begin();
                        leaf_val.write(write_iter, FRI::field_element_type::length());

                        if (interpolant.evaluate(alpha) != proof.round_proofs[i].colinear_value[0]) {
                            return false;
                        }
                        transcript(proof.round_proofs[i].colinear_path.root());
                        if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                            return false;
                        }
                        x = x_next;
                    }

                    // check the final polynomial against its root
                    auto final_root = commit<FRI>(precommit<FRI>(proof.final_polynomials[0], fri_params.D[r - 1]));
                    if (final_root != proof.round_proofs[r - 2].colinear_path.root()) {
                        return false;
                    }
                    if (proof.final_polynomials[0].degree() >
                        std::pow(2, std::log2(fri_params.max_degree + 1) - r + 1) - 1) {
                        return false;
                    }

                    return true;
                }
            }    // namespace algorithms
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP

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

#ifndef CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP
#define CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {

                    template<typename FieldType>
                    math::polynomial<typename FieldType::value_type>
                        fold_polynomial(math::polynomial<typename FieldType::value_type> &f,
                                        typename FieldType::value_type alpha) {

                        std::size_t d = f.degree();
                        if (d % 2 == 0) {
                            f.push_back(0);
                            d++;
                        }
                        math::polynomial<typename FieldType::value_type> f_folded(d / 2 + 1);

                        for (std::size_t index = 0; index <= f_folded.degree(); index++) {
                            f_folded[index] = f[2 * index] + alpha * f[2 * index + 1];
                        }

                        return f_folded;
                    }

                    template<typename FieldType>
                    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>>
                        calculate_domain_set(const std::size_t max_domain_degree, const std::size_t set_size) {

                        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set(set_size);
                        for (std::size_t i = 0; i < set_size; i++) {
                            const std::size_t domain_size = std::pow(2, max_domain_degree - i);
                            std::shared_ptr<math::evaluation_domain<FieldType>> domain =
                                math::make_evaluation_domain<FieldType>(domain_size);
                            domain_set[i] = domain;
                        }
                        return domain_set;
                    }

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
                             typename MerkleTreeHashType,
                             typename TranscriptHashType,
                             std::size_t M = 2>
                    struct basic_fri {

                        constexpr static const std::size_t m = M;

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
                                return r == rhs.r && max_degree == rhs.max_degree && D == rhs.D && q == rhs.q;
                            }
                            bool operator!=(const params_type &rhs) const {
                                return !(rhs == *this);
                            }

                            std::size_t r;
                            std::size_t max_degree;
                            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;

                            math::polynomial<typename FieldType::value_type> q;
                        };

                        struct round_proof_type {
                            bool operator==(const round_proof_type &rhs) const {
                                return y == rhs.y && p == rhs.p && T_root == rhs.T_root &&
                                       colinear_value == rhs.colinear_value && colinear_path == rhs.colinear_path;
                            }
                            bool operator!=(const round_proof_type &rhs) const {
                                return !(rhs == *this);
                            }
                            std::array<typename FieldType::value_type, m> y;
                            std::array<merkle_proof_type, m> p;

                            typename merkle_tree_type::value_type T_root;

                            typename FieldType::value_type colinear_value;
                            merkle_proof_type colinear_path;
                        };

                        struct proof_type {
                            bool operator==(const proof_type &rhs) const {
                                return round_proofs == rhs.round_proofs && final_polynomial == rhs.final_polynomial;
                            }
                            bool operator!=(const proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            std::vector<round_proof_type> round_proofs;    // 0..r-2

                            math::polynomial<typename FieldType::value_type> final_polynomial;
                        };

                        static precommitment_type
                            precommit(const math::polynomial<typename FieldType::value_type> &f,
                                      const std::shared_ptr<math::evaluation_domain<FieldType>> &D) {

                            std::vector<std::array<std::uint8_t, field_element_type::length()>> y_data;
                            y_data.resize(D->m);
                            std::vector<typename FieldType::value_type> f_dfs(f.begin(), f.end());    // for FFT
                            D->fft(f_dfs);

                            for (std::size_t i = 0; i < D->m; i++) {
                                field_element_type y_val(f_dfs[i]);
                                auto write_iter = y_data[i].begin();
                                y_val.write(write_iter, field_element_type::length());
                            }

                            return precommitment_type(y_data.begin(), y_data.end());
                        }

                        template<std::size_t list_size>
                        static std::array<precommitment_type, list_size>
                            precommit(const std::array<math::polynomial<typename FieldType::value_type>, list_size> &poly,
                                      const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {
                            std::array<precommitment_type, list_size> precommits;
                            for (std::size_t i = 0; i < list_size; i++) {
                                precommits[i] = precommit(poly[i], domain);
                            }
                            return precommits;
                        }

                        static commitment_type commit(precommitment_type P) {
                            return P.root();
                        }

                        template<std::size_t list_size>
                        static std::array<commitment_type, list_size>
                            commit(std::array<precommitment_type, list_size> P) {

                            std::array<commitment_type, list_size> commits;
                            for (std::size_t i = 0; i < list_size; i++) {
                                commits[i] = commit(P);
                            }
                            return commits;
                        }

                        static commitment_type commit(math::polynomial<typename FieldType::value_type> &f,
                                                      const std::shared_ptr<math::evaluation_domain<FieldType>> &D) {
                            return commit(precommit(f, D));
                        }

                        static proof_type proof_eval(const math::polynomial<typename FieldType::value_type> &Q,
                                                     const math::polynomial<typename FieldType::value_type> &g,
                                                     precommitment_type &T,
                                                     const params_type &fri_params,
                                                     transcript_type &transcript = transcript_type()) {

                            proof_type proof;

                            math::polynomial<typename FieldType::value_type> f = Q;    // copy?

                            // TODO: how to sample x?
                            std::size_t domain_size = fri_params.D[0]->m;
                            std::size_t x_index = (transcript.template int_challenge<std::uint64_t>())%domain_size;
                            std::size_t x_next_index;
                            typename FieldType::value_type x =
                                fri_params.D[0]->get_domain_element(1).pow(x_index);

                            std::size_t r = fri_params.r;

                            std::vector<round_proof_type> round_proofs;
                            std::unique_ptr<merkle_tree_type> p_tree = std::make_unique<merkle_tree_type>(T);
                            merkle_tree_type T_next;

                            for (std::size_t i = 0; i < r; i++) {

                                std::size_t domain_size = fri_params.D[i]->m;

                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = fri_params.q.evaluate(x);    // == x^2

                                x_index %= domain_size;

                                if (i < r-1){
                                    x_next_index = x_index % (fri_params.D[i + 1]->m);
                                }

                                math::polynomial<typename FieldType::value_type> f_next = fold_polynomial<FieldType>(
                                    f, alpha);    // create polynomial of degree (degree(f) / 2)

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                std::array<std::size_t, m> s_indices;
                                if constexpr (m == 2) {
                                    s[0] = x;
                                    s[1] = -x;
                                    s_indices[0] = x_index;
                                    s_indices[1] = (x_index + domain_size/2)%domain_size;
                                } else {
                                    return {};
                                }

                                std::array<typename FieldType::value_type, m> y;

                                for (std::size_t j = 0; j < m; j++) {
                                    y[j] = (i == 0 ? g.evaluate(s[j]) : f.evaluate(s[j]));    // polynomial evaluation
                                }

                                std::array<merkle_proof_type, m> p;

                                for (std::size_t j = 0; j < m; j++) {

                                    p[j] = merkle_proof_type(*p_tree, s_indices[j]);
                                }

                                typename FieldType::value_type colinear_value =
                                    f_next.evaluate(x_next);    // polynomial evaluation

                                if (i < r - 1) {
                                    T_next = precommit(f_next, fri_params.D[i + 1]);    // new merkle tree
                                    transcript(commit(T_next));

                                    merkle_proof_type colinear_path = merkle_proof_type(T_next, x_next_index);

                                    round_proofs.push_back(
                                        round_proof_type({y, p, p_tree->root(), colinear_value, colinear_path}));

                                    p_tree = std::make_unique<merkle_tree_type>(T_next);
                                } else {
                                    merkle_proof_type colinear_path;

                                    round_proofs.push_back(
                                        round_proof_type({y, p, p_tree->root(), colinear_value, colinear_path}));
                                }

                                x = x_next;
                                x_index = x_next_index;
                                f = f_next;
                            }
                            return proof_type({round_proofs, f});
                        }

                        static bool verify_eval(proof_type &proof,
                                                params_type &fri_params,
                                                const math::polynomial<typename FieldType::value_type> &U,
                                                const math::polynomial<typename FieldType::value_type> &V,
                                                transcript_type &transcript = transcript_type()) {

                            std::size_t idx = transcript.template int_challenge<std::size_t>();
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1).pow(idx);

                            std::size_t r = fri_params.r;

                            for (std::size_t i = 0; i < r; i++) {
                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = fri_params.q.evaluate(x);

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                if constexpr (m == 2) {
                                    s[0] = x;
                                    s[1] = -x;
                                } else {
                                    return false;
                                }

                                for (std::size_t j = 0; j < m; j++) {
                                    typename FieldType::value_type leaf = proof.round_proofs[i].y[j];

                                    std::array<std::uint8_t, field_element_type::length()> leaf_data;

                                    field_element_type leaf_val(leaf);
                                    auto write_iter = leaf_data.begin();
                                    leaf_val.write(write_iter, field_element_type::length());

                                    if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                                        return false;
                                    }
                                }

                                std::array<typename FieldType::value_type, m> y;

                                for (std::size_t j = 0; j < m; j++) {
                                    if (i == 0) {
                                        y[j] = (proof.round_proofs[i].y[j] - U.evaluate(s[j])) / V.evaluate(s[j]);
                                    } else {
                                        y[j] = proof.round_proofs[i].y[j];
                                    }
                                }

                                std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>>
                                    interpolation_points {
                                        std::make_pair(s[0], y[0]),
                                        std::make_pair(s[1], y[1]),
                                    };

                                math::polynomial<typename FieldType::value_type> interpolant =
                                    math::lagrange_interpolation(interpolation_points);

                                typename FieldType::value_type leaf = proof.round_proofs[i].colinear_value;

                                std::array<std::uint8_t, field_element_type::length()> leaf_data;
                                field_element_type leaf_val(leaf);
                                auto write_iter = leaf_data.begin();
                                leaf_val.write(write_iter, field_element_type::length());

                                if (interpolant.evaluate(alpha) != proof.round_proofs[i].colinear_value) {
                                    return false;
                                }
                                if (i < r - 1) {
                                    transcript(proof.round_proofs[i + 1].T_root);
                                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                                        return false;
                                    }
                                }
                                x = x_next;
                            }

                            if (proof.final_polynomial.degree() >
                                std::pow(2, std::log2(fri_params.max_degree + 1) - r) - 1) {
                                return false;
                            }
                            if (proof.final_polynomial.evaluate(x) != proof.round_proofs[r - 1].colinear_value) {
                                return false;
                            }

                            return true;
                        }
                    };
                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP

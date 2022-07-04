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

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>

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
                             std::size_t M,
                             std::size_t BatchSize>
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

                            // TODO: Better if we can construct params_type from any batch size to another
                            params_type(const typename basic_batched_fri<FieldType,
                                                                         MerkleTreeHashType,
                                                                         TranscriptHashType,
                                                                         M,
                                                                         1>::params_type &obj) {
                                r = obj.r;
                                max_degree = obj.max_degree;
                                D = obj.D;
                            }

                            params_type() {};

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
                            //     return !(rhs == *this;
                            // }
                            using colinear_value_t = typename select_container<(bool)leaf_size, typename FieldType::value_type, leaf_size>::type;

                            typename select_container<(bool)leaf_size,
                                                      std::array<typename FieldType::value_type, m>,
                                                      leaf_size>::type y;

                            std::array<merkle_proof_type, m> p;

                            typename merkle_tree_type::value_type T_root;
                            colinear_value_t colinear_value;

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
                            typename select_container<(bool)leaf_size,
                                                      math::polynomial<typename FieldType::value_type>,
                                                      leaf_size>::type final_polynomials;
                            commitment_type target_commitment;
                        };
                    };
                }    // namespace detail
            }        // namespace commitments

            namespace algorithms {
                template<typename FRI,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                    typename FRI::merkle_tree_hash_type,
                                                                                    typename FRI::transcript_hash_type,
                                                                                    FRI::m,
                                                                                    FRI::leaf_size>,
                                             FRI>::value,
                             bool>::type = true>
                static typename FRI::commitment_type commit(typename FRI::precommitment_type P) {
                    return P.root();
                }

                template<typename FRI, std::size_t list_size,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                    typename FRI::merkle_tree_hash_type,
                                                                                    typename FRI::transcript_hash_type,
                                                                                    FRI::m,
                                                                                    FRI::leaf_size>,
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
                                                                                    FRI::m,
                                                                                    FRI::leaf_size>,
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
                                                                                    FRI::m, FRI::leaf_size>,
                                             FRI>::value,
                             bool>::type = true>
                static typename FRI::precommitment_type
                    precommit(const math::polynomial<typename FRI::field_type::value_type> &f,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                    math::polynomial_dfs<typename FRI::field_type::value_type> f_dfs;
                    f_dfs.from_coefficients(f);

                    return precommit<FRI>(f_dfs, D);
                }

                template<typename FRI, typename ContainerType,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                    typename FRI::merkle_tree_hash_type,
                                                                                    typename FRI::transcript_hash_type,
                                                                                    FRI::m, FRI::leaf_size>,
                                             FRI>::value,
                             bool>::type = true>
                static typename std::enable_if<
                    (std::is_same<typename ContainerType::value_type,
                                  math::polynomial_dfs<typename FRI::field_type::value_type>>::value),
                    typename FRI::precommitment_type>::type
                    precommit(ContainerType poly,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                    auto begin = std::chrono::high_resolution_clock::now();
                    auto last = begin;
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::high_resolution_clock::now() - last);
#endif
                    for (int i = 0; i < poly.size(); ++i) {
                        // assert (poly[i].size() == D->size());
                        if (poly[i].size() != D->size()) {
                            poly[i].resize(D->size());
                        }
                    }

                    std::size_t list_size = poly.size();
                    std::vector<std::vector<std::uint8_t>> y_data(D->size());

                    for (std::size_t i = 0; i < D->size(); i++) {
                        y_data[i].resize(FRI::field_element_type::length() * list_size);
                        for (std::size_t j = 0; j < list_size; j++) {

                            typename FRI::field_element_type y_val(poly[j][i]);
                            auto write_iter = y_data[i].begin() + FRI::field_element_type::length() * j;
                            y_val.write(write_iter, FRI::field_element_type::length());
                        }
                    }

                    return containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, FRI::m>(y_data.begin(),
                                                                                                     y_data.end());
                }

                template<typename FRI, typename ContainerType,
                         typename std::enable_if<
                             std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                                    typename FRI::merkle_tree_hash_type,
                                                                                    typename FRI::transcript_hash_type,
                                                                                    FRI::m,
                                                                                    FRI::leaf_size>,
                                             FRI>::value,
                             bool>::type = true>
                static typename std::enable_if<
                    (std::is_same<typename ContainerType::value_type,
                                  math::polynomial<typename FRI::field_type::value_type>>::value),
                    typename FRI::precommitment_type>::type
                    precommit(const ContainerType &poly,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                    std::size_t list_size = poly.size();
                    std::vector<math::polynomial_dfs<typename FRI::field_type::value_type>> poly_dfs(list_size);
                    for (std::size_t i = 0; i < list_size; i++) {
                        poly_dfs[i].from_coefficients(poly[i]);
                        poly_dfs[i].resize(D->size());
                    }

                    return precommit<FRI>(poly_dfs, D);
                }

                template<typename FRI, typename ContainerType,
                    typename std::enable_if<
                        std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                               typename FRI::merkle_tree_hash_type,
                                                                               typename FRI::transcript_hash_type,
                                                                               FRI::m, FRI::leaf_size>,
                                        FRI>::value &&
                            (!std::is_same_v<typename ContainerType::value_type, typename FRI::field_type::value_type>),
                        bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(ContainerType f,
                               ContainerType g,
                               typename FRI::precommitment_type &T,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                 typename ContainerType::value_type>) {
                        for (int i = 0; i < f.size(); ++i) {
                            // assert(g[i].size() == fri_params.D[0]->size());
                            if (f[i].size() != fri_params.D[0]->size()) {
                                f[i].resize(fri_params.D[0]->size());
                            }
                            if (g[i].size() != fri_params.D[0]->size()) {
                                g[i].resize(fri_params.D[0]->size());
                            }
                        }
                    }

                    assert(f.size() == g.size());
                    std::size_t leaf_size = f.size();

                    transcript(commit<FRI>(T));

                    // TODO: how to sample x?
                    std::size_t domain_size = fri_params.D[0]->size();
                    std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                    typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

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

                        typename select_container<(bool)FRI::leaf_size,
                                                  std::array<typename FRI::field_type::value_type, FRI::m>,
                                                  FRI::leaf_size>::type y;
                        if constexpr (FRI::leaf_size == 0) {
                            y.resize(leaf_size);
                        }

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            for (std::size_t j = 0; j < FRI::m; j++) {
                                if (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                   typename ContainerType::value_type>) {
                                    y[polynom_index][j] =
                                        i == 0 ? g[polynom_index][s_indices[j]] : f[polynom_index][s_indices[j]];
                                } else {
                                    y[polynom_index][j] =
                                        i == 0 ? g[polynom_index].evaluate(s[j]) : f[polynom_index].evaluate(s[j]);
                                }
                            }
                        }

                        std::array<typename FRI::merkle_proof_type, FRI::m> p;

                        for (std::size_t j = 0; j < FRI::m; j++) {
                            p[j] = typename FRI::merkle_proof_type(*p_tree, s_indices[j]);
                        }

                        typename FRI::round_proof_type::colinear_value_t colinear_value;

                        if constexpr (FRI::leaf_size == 0) {
                            colinear_value.resize(leaf_size);
                        }

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                         typename ContainerType::value_type>) {
                                if (i == 0) {
                                    f[polynom_index].resize(fri_params.D[i]->size());
                                }
                                f[polynom_index] = commitments::detail::fold_polynomial<typename FRI::field_type>(
                                    f[polynom_index], alpha, fri_params.D[i]);
                            } else {
                                f[polynom_index] = commitments::detail::fold_polynomial<typename FRI::field_type>(
                                    f[polynom_index], alpha);
                            }
                        }

                        x_index = x_index % (fri_params.D[i + 1]->size());
                        x = fri_params.D[i + 1]->get_domain_element(x_index);

                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                         typename ContainerType::value_type>) {
                                colinear_value[polynom_index] = f[polynom_index][x_index];
                            } else {
                                colinear_value[polynom_index] = f[polynom_index].evaluate(x);
                            }
                        }

                        T_next = precommit<FRI>(f, fri_params.D[i + 1]);    // new merkle tree
                        transcript(commit<FRI>(T_next));

                        typename FRI::merkle_proof_type colinear_path =
                            typename FRI::merkle_proof_type(T_next, x_index);

                        round_proofs.push_back(
                            typename FRI::round_proof_type({y, p, p_tree->root(), colinear_value, colinear_path}));

                        p_tree = std::make_unique<typename FRI::merkle_tree_type>(T_next);
                    }

                    typename select_container<(bool)FRI::leaf_size,
                                              math::polynomial<typename FRI::field_type::value_type>,
                                              FRI::leaf_size>::type final_polynomials;

                    if constexpr (FRI::leaf_size == 0) {
                        final_polynomials.resize(f.size());
                    }
                    if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                 typename ContainerType::value_type>) {
                        for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
                            final_polynomials[polynom_index] =
                                math::polynomial<typename FRI::field_type::value_type>(f[polynom_index].coefficients());
                        }
                    } else {
                        for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
                            final_polynomials[polynom_index] = f[polynom_index];
                        }
                    }

                    return typename FRI::proof_type({round_proofs, final_polynomials, commit<FRI>(T)});
                }

                template<typename FRI, typename PolynomType,
                    typename std::enable_if<
                        std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                               typename FRI::merkle_tree_hash_type,
                                                                               typename FRI::transcript_hash_type,
                                                                               FRI::m, FRI::leaf_size>,
                                        FRI>::value &&
                            (std::is_same_v<typename PolynomType::value_type, typename FRI::field_type::value_type>),
                        bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(PolynomType f,
                               const PolynomType &g,
                               typename FRI::precommitment_type &T,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    std::array<PolynomType, 1> f_new = {f};
                    std::array<PolynomType, 1> g_new = {g};

                    return proof_eval<FRI>(f_new, g_new, T, fri_params, transcript);
                }

                template<typename FRI, typename ContainerType,
                    typename std::enable_if<
                        std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                               typename FRI::merkle_tree_hash_type,
                                                                               typename FRI::transcript_hash_type,
                                                                               FRI::m,
                                                                               FRI::leaf_size>,
                                        FRI>::value &&
                            !std::is_same_v<typename ContainerType::value_type, typename FRI::field_type::value_type>,
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
                                    y[j] =
                                        (proof.round_proofs[i].y[polynom_index][j] - U[polynom_index].evaluate(s[j])) /
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

                            typename FRI::field_type::value_type leaf =
                                proof.round_proofs[i].colinear_value[polynom_index];

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
                    typename std::enable_if<
                        std::is_base_of<commitments::detail::basic_batched_fri<typename FRI::field_type,
                                                                               typename FRI::merkle_tree_hash_type,
                                                                               typename FRI::transcript_hash_type,
                                                                               FRI::m,
                                                                               FRI::leaf_size>,
                                        FRI>::value, bool>::type = true>
                static bool verify_eval(typename FRI::proof_type &proof,
                                        typename FRI::params_type &fri_params,
                                        const math::polynomial<typename FRI::field_type::value_type> U,
                                        const math::polynomial<typename FRI::field_type::value_type> V,
                                        typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {

                    std::size_t leaf_size = FRI::leaf_size;
                    if constexpr (FRI::leaf_size == 0) {
                        leaf_size = proof.final_polynomials.size();
                    }
                        
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
                                    y[j] =
                                        (proof.round_proofs[i].y[polynom_index][j] - U.evaluate(s[j])) /
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

                            typename FRI::field_type::value_type leaf =
                                proof.round_proofs[i].colinear_value[polynom_index];

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

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                        if (proof.final_polynomials[polynom_index].degree() >
                            std::pow(2, std::log2(fri_params.max_degree + 1) - r + 1) - 1) {
                            return false;
                        }
                    }

                    return true;
                }
            }    // namespace algorithms
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP

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

#ifndef CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_HPP
#define CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_HPP

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
                    template<typename FieldType, typename MerkleTreeHashType, typename TranscriptHashType,
                            std::size_t M = 2>
                    struct basic_batched_fri {

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
                        using params_type =
                                typename basic_fri<FieldType, MerkleTreeHashType, TranscriptHashType, M>::params_type;

                        struct round_proof_type {
                            // bool operator==(const round_proof_type &rhs) const {
                            //     return y == rhs.y && p == rhs.p && T_root == rhs.T_root &&
                            //            colinear_value == rhs.colinear_value && colinear_path == rhs.colinear_path;
                            // }
                            // bool operator!=(const round_proof_type &rhs) const {
                            //     return !(rhs == *this);
                            // }
                            // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y;
                            std::vector<std::array<typename FieldType::value_type, m>> y;
                            std::array<merkle_proof_type, m> p;

                            typename merkle_tree_type::value_type T_root;

                            // std::array<typename FieldType::value_type, leaf_size> colinear_value;
                            std::vector<typename FieldType::value_type> colinear_value;
                            merkle_proof_type colinear_path;
                        };

                        struct proof_type {
                            // bool operator==(const proof_type &rhs) const {
                            //     return round_proofs == rhs.round_proofs && final_polynomials ==
                            //     rhs.final_polynomials;
                            // }
                            // bool operator!=(const proof_type &rhs) const {
                            //     return !(rhs == *this);
                            // }

                            std::vector<round_proof_type> round_proofs;    // 0..r-2

                            // std::array<math::polynomial<typename FieldType::value_type>,
                            //     leaf_size> final_polynomials;
                            std::vector<math::polynomial<typename FieldType::value_type>> final_polynomials;

                            commitment_type target_commitment;
                        };

                        template<typename ContainerType>
                        static typename std::enable_if<
                                (std::is_same<typename ContainerType::value_type,
                                        math::polynomial_dfs<typename FieldType::value_type>>::value),
                                precommitment_type>::type
                        precommit(ContainerType poly,
                                  const std::shared_ptr<math::evaluation_domain<FieldType>> &D) {

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
                                y_data[i].resize(field_element_type::length() * list_size);
                                for (std::size_t j = 0; j < list_size; j++) {

                                    field_element_type y_val(poly[j][i]);
                                    auto write_iter = y_data[i].begin() + field_element_type::length() * j;
                                    y_val.write(write_iter, field_element_type::length());
                                }
                            }
                            //#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            //                                elapsed =
                            //                                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                            //                                - last); std::cout << "------Batched FRI precommit
                            //                                marshalling, time: " << elapsed.count() << "ms" <<
                            //                                std::endl; last =
                            //                                std::chrono::high_resolution_clock::now();
                            //#endif

                            //#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            //                                elapsed =
                            //                                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                            //                                - last); std::cout << "------Batched FRI precommit merkle
                            //                                tree, time: " << elapsed.count() << "ms"  << std::endl;
                            //                                last = std::chrono::high_resolution_clock::now();
                            //                                elapsed =
                            //                                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                            //                                - begin); std::cout << "----Batched FRI precommit, time: "
                            //                                << elapsed.count() << "ms"  << std::endl;
                            //#endif
                            return containers::make_merkle_tree<typename precommitment_type::hash_type, m>(
                                    y_data.begin(),
                                    y_data.end());
                        }

                        template<typename ContainerType>
                        static typename std::enable_if<
                                (std::is_same<typename ContainerType::value_type,
                                        math::polynomial<typename FieldType::value_type>>::value),
                                precommitment_type>::type
                        precommit(const ContainerType &poly,
                                  const std::shared_ptr<math::evaluation_domain<FieldType>> &D) {

                            std::size_t list_size = poly.size();
                            std::vector<math::polynomial_dfs<typename FieldType::value_type>> poly_dfs(list_size);
                            for (std::size_t i = 0; i < list_size; i++) {
                                poly_dfs[i].from_coefficients(poly[i]);
                                poly_dfs[i].resize(D->size());
                            }

                            return precommit(poly_dfs, D);
                        }

                        static commitment_type commit(precommitment_type P) {
                            return P.root();
                        }

                        template<typename ContainerType>
                        static commitment_type commit(const ContainerType &poly,
                                                      const std::shared_ptr<math::evaluation_domain<FieldType>> &D) {
                            return commit(precommit(poly, D));
                        }

                        template<typename ContainerType>
                        static typename std::enable_if<
                                (std::is_same<typename ContainerType::value_type,
                                        math::polynomial_dfs<typename FieldType::value_type>>::value),
                                proof_type>::type
                        proof_eval(ContainerType f,
                                   ContainerType g,
                                   precommitment_type &T,
                                   const params_type &fri_params,
                                   transcript_type &transcript = transcript_type()) {

                            //#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            //                        auto begin = std::chrono::high_resolution_clock::now();
                            //                        auto last = begin;
                            //                        auto elapsed =
                            //                        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                            //                        - last); std::cout << "--Batched FRI:" << std::endl;
                            //#endif

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

                            transcript(commit(T));

                            // TODO: how to sample x?
                            std::size_t domain_size = fri_params.D[0]->size();
                            std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                            std::size_t r = fri_params.r;

                            std::vector<round_proof_type> round_proofs;
                            std::unique_ptr<merkle_tree_type> p_tree = std::make_unique<merkle_tree_type>(T);
                            merkle_tree_type T_next;

                            for (std::size_t i = 0; i < r - 1; i++) {

                                std::size_t domain_size = fri_params.D[i]->size();

                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                x_index %= domain_size;

                                // m = 2, so:
                                std::array<std::size_t, m> s_indices;
                                if constexpr (m == 2) {
                                    s_indices[0] = x_index;
                                    s_indices[1] = (x_index + domain_size / 2) % domain_size;
                                } else {
                                    return {};
                                }

                                // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y;
                                std::vector<std::array<typename FieldType::value_type, m>> y(leaf_size);

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    for (std::size_t j = 0; j < m; j++) {
                                        y[polynom_index][j] =
                                                (i == 0 ? g[polynom_index][s_indices[j]] :
                                                 f[polynom_index][s_indices[j]]);    // polynomial evaluation
                                    }
                                }

                                std::array<merkle_proof_type, m> p;

                                for (std::size_t j = 0; j < m; j++) {

                                    p[j] = merkle_proof_type(*p_tree, s_indices[j]);
                                }

                                // std::array<typename FieldType::value_type, leaf_size> colinear_value;
                                std::vector<typename FieldType::value_type> colinear_value(leaf_size);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
//                                last = std::chrono::high_resolution_clock::now();
#endif
                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    if (i == 0) {
                                        f[polynom_index].resize(fri_params.D[i]->size());
                                    }
                                    f[polynom_index] =
                                            fold_polynomial<FieldType>(f[polynom_index], alpha, fri_params.D[i]);
                                }

                                //#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                                //                                elapsed =
                                //                                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                                //                                - last); std::cout << "----Batched FRI fold polynomial
                                //                                round " << i << ", time: " << elapsed.count() << "ms"
                                //                                << std::endl; last =
                                //                                std::chrono::high_resolution_clock::now();
                                //#endif

                                x_index = x_index % (fri_params.D[i + 1]->size());

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    colinear_value[polynom_index] =
                                            f[polynom_index][x_index];    // polynomial evaluation
                                }

                                T_next = precommit(f, fri_params.D[i + 1]);    // new merkle tree

                                transcript(commit(T_next));

                                merkle_proof_type colinear_path = merkle_proof_type(T_next, x_index);

                                round_proofs.push_back(
                                        round_proof_type({y, p, p_tree->root(), colinear_value, colinear_path}));

                                p_tree = std::make_unique<merkle_tree_type>(T_next);
                            }

                            std::vector<math::polynomial<typename FieldType::value_type>> final_polynomials(f.size());

                            for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
                                final_polynomials[polynom_index] =
                                        math::polynomial<typename FieldType::value_type>(
                                                f[polynom_index].coefficients());
                            }

                            proof_type proof({round_proofs, final_polynomials, commit(T)});

                            //#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            //                        elapsed =
                            //                        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                            //                        - begin); std::cout << "--Batched FRI, total time: " <<
                            //                        elapsed.count() << "ms" << std::endl;
                            //#endif
                            return proof;
                        }

                        template<typename ContainerType>
                        static typename std::enable_if<
                                (std::is_same<typename ContainerType::value_type,
                                        math::polynomial<typename FieldType::value_type>>::value),
                                proof_type>::type
                        proof_eval(ContainerType f,
                                   const ContainerType &g,
                                   precommitment_type &T,
                                   const params_type &fri_params,
                                   transcript_type &transcript = transcript_type()) {

                            assert(f.size() == g.size());
                            std::size_t leaf_size = f.size();

                            transcript(commit(T));

                            // TODO: how to sample x?
                            std::size_t domain_size = fri_params.D[0]->size();
                            std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;

                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(x_index);

                            std::size_t r = fri_params.r;

                            std::vector<round_proof_type> round_proofs;
                            std::unique_ptr<merkle_tree_type> p_tree = std::make_unique<merkle_tree_type>(T);
                            merkle_tree_type T_next;

                            for (std::size_t i = 0; i < r - 1; i++) {

                                std::size_t domain_size = fri_params.D[i]->size();

                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                x_index %= domain_size;

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                std::array<std::size_t, m> s_indices;
                                if constexpr (m == 2) {
                                    s[0] = x;
                                    s[1] = -x;
                                    s_indices[0] = x_index;
                                    s_indices[1] = (x_index + domain_size / 2) % domain_size;
                                } else {
                                    return {};
                                }

                                // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y;
                                std::vector<std::array<typename FieldType::value_type, m>> y(leaf_size);

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    for (std::size_t j = 0; j < m; j++) {
                                        y[polynom_index][j] =
                                                (i == 0 ? g[polynom_index].evaluate(s[j]) :
                                                 f[polynom_index].evaluate(s[j]));    // polynomial evaluation
                                    }
                                }

                                std::array<merkle_proof_type, m> p;

                                for (std::size_t j = 0; j < m; j++) {

                                    p[j] = merkle_proof_type(*p_tree, s_indices[j]);
                                }

                                // std::array<typename FieldType::value_type, leaf_size> colinear_value;
                                std::vector<typename FieldType::value_type> colinear_value(leaf_size);

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    f[polynom_index] = fold_polynomial<FieldType>(f[polynom_index], alpha);
                                }

                                x_index = x_index % (fri_params.D[i + 1]->size());
                                x = fri_params.D[i + 1]->get_domain_element(x_index);

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    colinear_value[polynom_index] =
                                            f[polynom_index].evaluate(x);    // polynomial evaluation
                                }

                                T_next = precommit(f, fri_params.D[i + 1]);    // new merkle tree
                                transcript(commit(T_next));

                                merkle_proof_type colinear_path = merkle_proof_type(T_next, x_index);

                                round_proofs.push_back(
                                        round_proof_type({y, p, p_tree->root(), colinear_value, colinear_path}));

                                p_tree = std::make_unique<merkle_tree_type>(T_next);
                            }

                            std::vector<math::polynomial<typename FieldType::value_type>> final_polynomials(f.begin(),
                                                                                                            f.end());

                            return proof_type({round_proofs, final_polynomials, commit(T)});
                        }

                        template<typename ContainerType>
                        static bool verify_eval(proof_type &proof,
                                                params_type &fri_params,
                                                const ContainerType U,
                                                const ContainerType V,
                                                transcript_type &transcript = transcript_type()) {

                            assert(U.size() == V.size());
                            std::size_t leaf_size = U.size();

                            transcript(proof.target_commitment);

                            std::size_t domain_size = fri_params.D[0]->size();
                            std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(x_index);

                            std::size_t r = fri_params.r;

                            for (std::size_t i = 0; i < r - 1; i++) {
                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = x * x;

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                if constexpr (m == 2) {
                                    s[0] = x;
                                    s[1] = -x;
                                } else {
                                    return false;
                                }

                                for (std::size_t j = 0; j < m; j++) {
                                    std::vector<std::uint8_t> leaf_data(field_element_type::length() * leaf_size);

                                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                                        typename FieldType::value_type leaf = proof.round_proofs[i].y[polynom_index][j];

                                        field_element_type leaf_val(leaf);
                                        auto write_iter =
                                                leaf_data.begin() + field_element_type::length() * polynom_index;
                                        leaf_val.write(write_iter, field_element_type::length());
                                    }

                                    if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                                        return false;
                                    }
                                }

                                std::vector<std::uint8_t> leaf_data(field_element_type::length() * leaf_size);

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                                    std::array<typename FieldType::value_type, m> y;

                                    for (std::size_t j = 0; j < m; j++) {
                                        if (i == 0) {
                                            y[j] = (proof.round_proofs[i].y[polynom_index][j] -
                                                    U[polynom_index].evaluate(s[j])) /
                                                   V[polynom_index].evaluate(s[j]);
                                        } else {
                                            y[j] = proof.round_proofs[i].y[polynom_index][j];
                                        }
                                    }

                                    std::vector<
                                            std::pair<typename FieldType::value_type, typename FieldType::value_type>>
                                            interpolation_points{
                                            std::make_pair(s[0], y[0]),
                                            std::make_pair(s[1], y[1]),
                                    };

                                    math::polynomial<typename FieldType::value_type> interpolant =
                                            math::lagrange_interpolation(interpolation_points);

                                    typename FieldType::value_type leaf =
                                            proof.round_proofs[i].colinear_value[polynom_index];

                                    field_element_type leaf_val(leaf);
                                    auto write_iter = leaf_data.begin() + field_element_type::length() * polynom_index;
                                    leaf_val.write(write_iter, field_element_type::length());

                                    if (interpolant.evaluate(alpha) !=
                                        proof.round_proofs[i].colinear_value[polynom_index]) {
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

                        template<typename ContainerType>
                        static bool verify_eval(proof_type &proof,
                                                params_type &fri_params,
                                                const ContainerType U,
                                                const math::polynomial<typename FieldType::value_type>
                                                V,
                                                transcript_type &transcript = transcript_type()) {

                            std::size_t leaf_size = U.size();
                            transcript(proof.target_commitment);

                            std::size_t domain_size = fri_params.D[0]->size();
                            std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(x_index);

                            std::size_t r = fri_params.r;

                            for (std::size_t i = 0; i < r - 1; i++) {
                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = x * x;

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                if constexpr (m == 2) {
                                    s[0] = x;
                                    s[1] = -x;
                                } else {
                                    return false;
                                }

                                for (std::size_t j = 0; j < m; j++) {
                                    std::vector<std::uint8_t> leaf_data(field_element_type::length() * leaf_size);

                                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                                        typename FieldType::value_type leaf = proof.round_proofs[i].y[polynom_index][j];

                                        field_element_type leaf_val(leaf);
                                        auto write_iter =
                                                leaf_data.begin() + field_element_type::length() * polynom_index;
                                        leaf_val.write(write_iter, field_element_type::length());
                                    }

                                    if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                                        return false;
                                    }
                                }

                                std::vector<std::uint8_t> leaf_data(field_element_type::length() * leaf_size);

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                                    std::array<typename FieldType::value_type, m> y;

                                    for (std::size_t j = 0; j < m; j++) {
                                        if (i == 0) {
                                            y[j] = (proof.round_proofs[i].y[polynom_index][j] -
                                                    U[polynom_index].evaluate(s[j])) /
                                                   V.evaluate(s[j]);
                                        } else {
                                            y[j] = proof.round_proofs[i].y[polynom_index][j];
                                        }
                                    }

                                    std::vector<
                                            std::pair<typename FieldType::value_type, typename FieldType::value_type>>
                                            interpolation_points{
                                            std::make_pair(s[0], y[0]),
                                            std::make_pair(s[1], y[1]),
                                    };

                                    math::polynomial<typename FieldType::value_type> interpolant =
                                            math::lagrange_interpolation(interpolation_points);

                                    typename FieldType::value_type leaf =
                                            proof.round_proofs[i].colinear_value[polynom_index];

                                    field_element_type leaf_val(leaf);
                                    auto write_iter = leaf_data.begin() + field_element_type::length() * polynom_index;
                                    leaf_val.write(write_iter, field_element_type::length());

                                    if (interpolant.evaluate(alpha) !=
                                        proof.round_proofs[i].colinear_value[polynom_index]) {
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
                    };
                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_HPP

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

#ifndef CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_COMPILE_TIME_SIZE_HPP
#define CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_COMPILE_TIME_SIZE_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>

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
                            std::size_t M = 2,
                            std::size_t BatchSize = 1>
                    struct basic_batched_fri_compile_time_size {

                        constexpr static const std::size_t
                        m = M;
                        constexpr static const std::size_t
                        leaf_size = BatchSize;

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
                        using params_type = typename basic_fri<FieldType, MerkleTreeHashType,
                                TranscriptHashType, M>::params_type;

                        struct round_proof_type {
                            std::array <std::array<typename FieldType::value_type, m>, leaf_size> y;
                            std::array <merkle_proof_type, m> p;

                            typename merkle_tree_type::value_type T_root;

                            std::array<typename FieldType::value_type, leaf_size> colinear_value;
                            merkle_proof_type colinear_path;

                            bool operator==(const round_proof_type &rhs) const {
                                return y == rhs.y && p == rhs.p && T_root == rhs.T_root &&
                                       colinear_value == rhs.colinear_value && colinear_path == rhs.colinear_path;
                            }

                            bool operator!=(const round_proof_type &rhs) const {
                                return !(rhs == *this);
                            }
                        };

                        struct proof_type {
                            bool operator==(const proof_type &rhs) const {
                                return round_proofs == rhs.round_proofs && final_polynomials == rhs.final_polynomials;
                            }

                            bool operator!=(const proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            std::vector <round_proof_type> round_proofs;    // 0..r-2

                            std::array <math::polynomial<typename FieldType::value_type>,
                            leaf_size> final_polynomials;
                        };

                        template<std::size_t list_size>
                        static precommitment_type precommit(
                                const std::array <math::polynomial<typename FieldType::value_type>, list_size> &poly,
                                const std::shared_ptr <math::evaluation_domain<FieldType>> &D) {

                            std::vector <std::array<std::uint8_t, field_element_type::length() * list_size>> y_data;
                            y_data.resize(D->m);
                            std::array <std::vector<typename FieldType::value_type>, list_size> poly_dfs;
                            for (std::size_t i = 0; i < list_size; i++) {
                                poly_dfs[i].resize(poly[i].size());
                                std::copy(poly[i].begin(), poly[i].end(), poly_dfs[i].begin());
                                D->fft(poly_dfs[i]);
                            }

                            for (std::size_t i = 0; i < D->m; i++) {
                                for (std::size_t j = 0; j < list_size; j++) {

                                    field_element_type y_val(poly_dfs[j][i]);
                                    auto write_iter = y_data[i].begin() + field_element_type::length() * j;
                                    y_val.write(write_iter, field_element_type::length());
                                }
                            }

                            return precommitment_type(y_data.begin(), y_data.end());
                        }

                        static commitment_type commit(precommitment_type P) {
                            return P.root();
                        }

                        static commitment_type commit(math::polynomial<typename FieldType::value_type> &f,
                                                      const std::shared_ptr <math::evaluation_domain<FieldType>> &D) {
                            return commit(precommit(f, D));
                        }

                        static proof_type
                        proof_eval(const std::array <math::polynomial<typename FieldType::value_type>, leaf_size> Q,
                                   const std::array <math::polynomial<typename FieldType::value_type>, leaf_size>
                                   g,
                                   precommitment_type &T,
                                   const params_type &fri_params,
                                   transcript_type &transcript = transcript_type()) {

                            proof_type proof;

                            std::array <math::polynomial<typename FieldType::value_type>, leaf_size> f = Q;    // copy?

                            // TODO: how to sample x?
                            std::size_t domain_size = fri_params.D[0]->m;
                            std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                            std::uint64_t x_next_index;
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1).pow(x_index);

                            std::size_t r = fri_params.r;

                            std::vector <round_proof_type> round_proofs;
                            std::unique_ptr <merkle_tree_type> p_tree = std::make_unique<merkle_tree_type>(T);
                            merkle_tree_type T_next;

                            for (std::size_t i = 0; i < r; i++) {

                                std::size_t domain_size = fri_params.D[i]->m;

                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = fri_params.q.evaluate(x);    // == x^2

                                x_index %= domain_size;

                                if (i < r - 1) {
                                    x_next_index = x_index % (fri_params.D[i + 1]->m);
                                }

                                std::array <math::polynomial<typename FieldType::value_type>, leaf_size> f_next;

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    f_next[polynom_index] = fold_polynomial<FieldType>(f[polynom_index], alpha);
                                }

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                std::array <std::size_t, m> s_indices;
                                if constexpr(m == 2)
                                {
                                    s[0] = x;
                                    s[1] = -x;
                                    s_indices[0] = x_index;
                                    s_indices[1] = (x_index + domain_size / 2) % domain_size;
                                } else {
                                    return {};
                                }

                                std::array <std::array<typename FieldType::value_type, m>, leaf_size> y;

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    for (std::size_t j = 0; j < m; j++) {
                                        y[polynom_index][j] =
                                                (i == 0 ? g[polynom_index].evaluate(s[j]) :
                                                 f[polynom_index].evaluate(s[j]));    // polynomial evaluation
                                    }
                                }

                                std::array <merkle_proof_type, m> p;

                                for (std::size_t j = 0; j < m; j++) {

                                    p[j] = merkle_proof_type(*p_tree, s_indices[j]);
                                }

                                std::array<typename FieldType::value_type, leaf_size> colinear_value;

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                    colinear_value[polynom_index] =
                                            f_next[polynom_index].evaluate(x_next);    // polynomial evaluation
                                }

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

                        static bool
                        verify_eval(proof_type &proof,
                                    params_type &fri_params,
                                    const std::array <math::polynomial<typename FieldType::value_type>, leaf_size>
                                    U,
                                    const std::array <math::polynomial<typename FieldType::value_type>, leaf_size>
                                    V,
                                    transcript_type &transcript = transcript_type()) {

                            std::uint64_t idx = transcript.template int_challenge<std::uint64_t>();
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1).pow(idx);

                            std::size_t r = fri_params.r;

                            for (std::size_t i = 0; i < r; i++) {
                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = fri_params.q.evaluate(x);

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                if constexpr(m == 2)
                                {
                                    s[0] = x;
                                    s[1] = -x;
                                } else {
                                    return false;
                                }

                                for (std::size_t j = 0; j < m; j++) {
                                    std::array < std::uint8_t, field_element_type::length() * leaf_size > leaf_data;

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

                                std::array < std::uint8_t, field_element_type::length() * leaf_size > leaf_data;

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

                                    std::vector <
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

                                if (i < r - 1) {
                                    transcript(proof.round_proofs[i + 1].T_root);
                                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                                        return false;
                                    }
                                }
                                x = x_next;
                            }

                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                                if (proof.final_polynomials[polynom_index].degree() >
                                    std::pow(2, std::log2(fri_params.max_degree + 1) - r) - 1) {
                                    return false;
                                }
                                if (proof.final_polynomials[polynom_index].evaluate(x) !=
                                    proof.round_proofs[r - 1].colinear_value[polynom_index]) {
                                    return false;
                                }

                            }

                            return true;
                        }

                        static bool
                        verify_eval(proof_type &proof,
                                    params_type &fri_params,
                                    const std::array <math::polynomial<typename FieldType::value_type>, leaf_size>
                                    U,
                                    const math::polynomial<typename FieldType::value_type> V,
                                    transcript_type &transcript = transcript_type()) {

                            std::uint64_t idx = transcript.template int_challenge<std::uint64_t>();
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1).pow(idx);

                            std::size_t r = fri_params.r;

                            for (std::size_t i = 0; i < r; i++) {
                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = fri_params.q.evaluate(x);

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                if constexpr(m == 2)
                                {
                                    s[0] = x;
                                    s[1] = -x;
                                } else {
                                    return false;
                                }

                                for (std::size_t j = 0; j < m; j++) {
                                    std::array < std::uint8_t, field_element_type::length() * leaf_size > leaf_data;

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

                                std::array < std::uint8_t, field_element_type::length() * leaf_size > leaf_data;

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

                                    std::vector <
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

                                if (i < r - 1) {
                                    transcript(proof.round_proofs[i + 1].T_root);
                                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                                        return false;
                                    }
                                }
                                x = x_next;
                            }

                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                                if (proof.final_polynomials[polynom_index].degree() >
                                    std::pow(2, std::log2(fri_params.max_degree + 1) - r) - 1) {
                                    return false;
                                }
                                if (proof.final_polynomials[polynom_index].evaluate(x) !=
                                    proof.round_proofs[r - 1].colinear_value[polynom_index]) {
                                    return false;
                                }

                            }

                            return true;
                        }

                        static bool verify_eval(proof_type &proof,
                                                params_type &fri_params,
                                                const math::polynomial<typename FieldType::value_type> U,
                                                const math::polynomial<typename FieldType::value_type> V,
                                                transcript_type &transcript = transcript_type()) {

                            std::size_t idx = transcript.template int_challenge<std::size_t>();
                            typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1).pow(idx);

                            std::size_t r = fri_params.r;

                            for (std::size_t i = 0; i < r; i++) {
                                typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                                typename FieldType::value_type x_next = fri_params.q.evaluate(x);

                                // m = 2, so:
                                std::array<typename FieldType::value_type, m> s;
                                if constexpr(m == 2)
                                {
                                    s[0] = x;
                                    s[1] = -x;
                                } else {
                                    return false;
                                }

                                for (std::size_t j = 0; j < m; j++) {
                                    std::array < std::uint8_t, field_element_type::length() * leaf_size > leaf_data;

                                    for (std::size_t polynom_index = 0; polynom_index < leaf_size;
                                         polynom_index++) {

                                        typename FieldType::value_type leaf = proof.round_proofs[i].y[polynom_index][j];

                                        field_element_type leaf_val(leaf);
                                        auto write_iter = leaf_data.begin() +
                                                          field_element_type::length() * polynom_index;
                                        leaf_val.write(write_iter, field_element_type::length());
                                    }

                                    if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                                        return false;
                                    }
                                }

                                std::array < std::uint8_t, field_element_type::length() * leaf_size > leaf_data;

                                for (std::size_t polynom_index = 0; polynom_index < leaf_size;
                                     polynom_index++) {

                                    std::array<typename FieldType::value_type, m> y;

                                    for (std::size_t j = 0; j < m; j++) {
                                        if (i == 0) {
                                            y[j] =
                                                    (proof.round_proofs[i].y[polynom_index][j] -
                                                     U.evaluate(s[j])) / V.evaluate(s[j]);
                                        } else {
                                            y[j] = proof.round_proofs[i].y[polynom_index][j];
                                        }
                                    }


                                    std::vector <std::pair<typename FieldType::value_type, typename FieldType::value_type>>
                                            interpolation_points{
                                            std::make_pair(s[0], y[0]),
                                            std::make_pair(s[1], y[1]),
                                    };

                                    math::polynomial<typename FieldType::value_type> interpolant =
                                            math::lagrange_interpolation(interpolation_points);

                                    typename FieldType::value_type leaf = proof.round_proofs[i].colinear_value[polynom_index];


                                    field_element_type leaf_val(leaf);
                                    auto write_iter = leaf_data.begin() + field_element_type::length() * polynom_index;
                                    leaf_val.write(write_iter, field_element_type::length());

                                    if (interpolant.evaluate(alpha) !=
                                        proof.round_proofs[i].colinear_value[polynom_index]) {
                                        return false;
                                    }
                                }

                                if (i < r - 1) {
                                    transcript(proof.round_proofs[i + 1].T_root);
                                    if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                                        return false;
                                    }
                                }
                                x = x_next;
                            }

                            for (std::size_t polynom_index = 0; polynom_index < leaf_size;
                                 polynom_index++) {

                                if (proof.final_polynomials[polynom_index].degree() >
                                    std::pow(2, std::log2(fri_params.max_degree + 1) - r) - 1) {
                                    return false;
                                }
                                if (proof.final_polynomials[polynom_index].evaluate(x) !=
                                    proof.round_proofs[r - 1].colinear_value[polynom_index]) {
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

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_COMPILE_TIME_SIZE_HPP

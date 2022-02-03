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

#ifndef CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/merkle/tree.hpp>
#include <nil/crypto3/merkle/proof.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

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
                template<typename FieldType, typename Hash, std::size_t M = 2>
                struct fri_commitment_scheme {
                    constexpr static const std::size_t m = M;

                    typedef FieldType field_type;
                    typedef Hash transcript_hash_type;

                    typedef typename containers::merkle_tree<Hash, 2> merkle_tree_type;
                    typedef typename containers::merkle_proof<Hash, 2> merkle_proof_type;

                    using Endianness = nil::marshalling::option::big_endian;
                    using field_element_type =
                            nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<Endianness>,
                                                                            FieldType>;

                    struct params_type {
                        std::size_t r;
                        std::size_t max_degree;
                        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;

                        math::polynomial::polynomial<typename FieldType::value_type> q;
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

                        math::polynomial::polynomial<typename FieldType::value_type> final_polynomial;
                    };

                    // The result of this function is not commitment_type (as it would expected),
                    // but the built Merkle tree. This is done so, because we often need to reuse
                    // the built Merkle tree
                    // After this function
                    // result.root();
                    // should be called
                    static merkle_tree_type
                        commit(math::polynomial::polynomial<typename FieldType::value_type> &f,
                               const std::shared_ptr<math::evaluation_domain<FieldType>> &D) {

                        std::vector<std::array<std::uint8_t, field_element_type::length()>> y_data;
                        y_data.resize(D->m);
                        std::vector<typename FieldType::value_type> tmp(f.begin(), f.end());
                        D->fft(tmp);

                        for (std::size_t i = 0; i < D->m; i++) {
                            field_element_type y_val =
                                nil::crypto3::marshalling::types::fill_field_element<FieldType, Endianness>(tmp[i]);
                            auto write_iter = y_data[i].begin();
                            y_val.write(write_iter, field_element_type::length());
                        }

                        return merkle_tree_type(y_data);
                    }

                    static inline math::polynomial::polynomial<typename FieldType::value_type> 
                    fold_polynomial(const math::polynomial::polynomial<typename FieldType::value_type> &f,
                            typename FieldType::value_type alpha) {
                        std::size_t d = f.degree();
                        BOOST_ASSERT_MSG(d % 2 != 0, "wrong using: fold_polynomial accepts only polynomials of odd degree");
                        math::polynomial::polynomial<typename FieldType::value_type> f_folded(d/2 + 1);

                        for (std::size_t index = 0; index <= f_folded.degree(); index++){
                            f_folded[index] = f[2*index] + alpha * f[2*index + 1];
                        }

                        return f_folded;
                    }

                    static proof_type proof_eval(const math::polynomial::polynomial<typename FieldType::value_type> &Q,
                                                 const math::polynomial::polynomial<typename FieldType::value_type> &g,
                                                 merkle_tree_type &T,
                                                 fiat_shamir_heuristic_updated<transcript_hash_type> &transcript,
                                                 params_type &fri_params) {

                        proof_type proof;

                        math::polynomial::polynomial<typename FieldType::value_type> f = Q;

                        //typename FieldType::value_type x = transcript.template challenge<FieldType>();
                        typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1);

                        std::size_t r = fri_params.r;

                        std::vector<round_proof_type> round_proofs;
                        math::polynomial::polynomial<typename FieldType::value_type> final_polynomial;

                        for (std::size_t i = 0; i <= r - 1; i++) {
                            
                            typename FieldType::value_type alpha = transcript.template challenge<FieldType>();

                            typename FieldType::value_type x_next = fri_params.q.evaluate(x);

                            math::polynomial::polynomial<typename FieldType::value_type> f_next = 
                                fold_polynomial(f, alpha);

                            // m = 2, so:
                            std::array<typename FieldType::value_type, m> s;
                            if constexpr (m == 2) {
                                s[0] = x;
                                s[1] = -x;
                            } else {
                                return {};
                            }

                            std::array<typename FieldType::value_type, m> y;

                            for (std::size_t j = 0; j < m; j++) {
                                y[j] = f.evaluate(s[j]);
                            }

                            std::array<merkle_proof_type, m> p;

                            for (std::size_t j = 0; j < m; j++) {
                                std::vector<typename FieldType::value_type> tmp(f.begin(), f.end());
                                fri_params.D[i]->fft(tmp);
                                if (i == 0) {

                                    typename FieldType::value_type leaf = g.evaluate(s[j]);
                                    std::cout<<leaf.data<<std::endl;
                                    
                                    std::size_t leaf_index = 0;
                                    for (; leaf_index < tmp.size(); leaf_index++){
                                        if (tmp[leaf_index] == leaf)
                                            break;
                                    }
                                    p[j] = merkle_proof_type(T, leaf_index);

                                    std::array<std::uint8_t, field_element_type::length()> leaf_data;

                                    field_element_type leaf_val =
                                        nil::crypto3::marshalling::types::fill_field_element<FieldType, Endianness>(leaf);
                                    auto write_iter = leaf_data.begin();
                                    leaf_val.write(write_iter, field_element_type::length());

                                    if (!p[j].validate(leaf_data)) {
                                        std::printf("s merkle generation failed: %ld\n", i);
                                    }
                                } else {
                                    for (std::size_t j = 0; j < m; j++) {

                                        typename FieldType::value_type leaf = y[j];

                                        std::size_t leaf_index = 0;
                                        for (; leaf_index < fri_params.D[i]->m; leaf_index++){
                                            if (tmp[leaf_index] == leaf)
                                                break;
                                        }
                                        p[j] = merkle_proof_type(T, leaf_index);

                                        std::array<std::uint8_t, field_element_type::length()> leaf_data;

                                        field_element_type leaf_val =
                                            nil::crypto3::marshalling::types::fill_field_element<FieldType, Endianness>(leaf);
                                        auto write_iter = leaf_data.begin();
                                        leaf_val.write(write_iter, field_element_type::length());

                                        if (!p[j].validate(leaf_data)) {
                                            std::printf("s merkle generation failed: %ld\n", i);
                                        }
                                    }
                                }
                            }

                            if (i < r - 1) {
                                merkle_tree_type T_next = commit(f_next, fri_params.D[i + 1]);
                                transcript(T_next.root());

                                typename FieldType::value_type colinear_value = f_next.evaluate(x_next);

                                std::size_t leaf_index = 0;
                                for (; leaf_index < fri_params.D[i + 1]->m; leaf_index++){
                                    if (fri_params.D[i + 1]->get_domain_element(leaf_index) == colinear_value)
                                        break;
                                }

                                merkle_proof_type colinear_path = merkle_proof_type(T_next, leaf_index);

                                round_proofs.push_back(
                                    round_proof_type({y, p, T.root(), colinear_value, colinear_path}));

                                T = T_next;
                            } else {
                                final_polynomial = f_next;
                            }

                            x = x_next;
                            f = f_next;
                        }
                        return proof_type({round_proofs, final_polynomial});
                    }

                    static bool verify_eval(proof_type &proof,
                                        fiat_shamir_heuristic_updated<transcript_hash_type> &transcript,
                                        params_type &fri_params,
                                        const math::polynomial::polynomial<typename FieldType::value_type> &U,
                                        const math::polynomial::polynomial<typename FieldType::value_type> &V) {

                        //typename FieldType::value_type x = transcript.template challenge<FieldType>();
                        typename FieldType::value_type x = fri_params.D[0]->get_domain_element(1);

                        std::size_t r = fri_params.r;

                        for (std::size_t i = 0; i <= r - 2; i++) {

                            std::printf("r: %ld\n", i);

                            typename FieldType::value_type alpha =
                                transcript.template challenge<FieldType>();

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

                                field_element_type leaf_val =
                                    nil::crypto3::marshalling::types::fill_field_element<FieldType, Endianness>(leaf);
                                auto write_iter = leaf_data.begin();
                                leaf_val.write(write_iter, field_element_type::length());

                                if (!proof.round_proofs[i].p[j].validate(leaf_data)) {
                                    std::printf("s merkle verification failed: %ld\n", i);
                                    return false;
                                }
                            }

                            std::array<typename FieldType::value_type, m> y;

                            for (std::size_t j = 0; j < m; j++) {
                                if (i == 0){
                                    y[j] = (proof.round_proofs[i].y[j] - U.evaluate(s[j]))/V.evaluate(s[j]);
                                } else {
                                    y[j] = proof.round_proofs[i].y[j];
                                }
                            }

                            if (i < r - 2){
                                transcript(proof.round_proofs[i + 1].T_root);
                            }

                            std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> interpolation_points {
                                std::make_pair(s[0], y[0]),
                                std::make_pair(s[1], y[1]),
                            };

                            math::polynomial::polynomial<typename FieldType::value_type> interpolant = 
                                math::polynomial::_lagrange_interpolation(interpolation_points);

                            typename FieldType::value_type leaf = proof.round_proofs[i].colinear_value;

                            std::array<std::uint8_t, field_element_type::length()> leaf_data;

                            field_element_type leaf_val =
                                nil::crypto3::marshalling::types::fill_field_element<FieldType, Endianness>(leaf);
                            auto write_iter = leaf_data.begin();
                            leaf_val.write(write_iter, field_element_type::length());

                            if (!proof.round_proofs[i].colinear_path.validate(leaf_data)){
                                std::printf("colinear merkle verification failed: %ld", i);
                                return false;
                            }
                            if (interpolant.evaluate(alpha) != proof.round_proofs[i].colinear_value){
                                std::printf("colinear check failed: %ld", i);
                                return false;
                            }

                            x = x_next;

                        }

                        if (proof.final_polynomial.degree() > 
                            std::pow(2, std::log2(fri_params.max_degree) - r)) {
                                return false;
                        }

                        if (proof.final_polynomial.evaluate(x) != proof.round_proofs[r - 2].colinear_value) {
                            return false;
                        }

                        return true;                        
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP

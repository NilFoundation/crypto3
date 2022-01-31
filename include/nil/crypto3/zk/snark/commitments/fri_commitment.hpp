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

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

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
                template<typename FieldType,
                         typename Hash,
                         std::size_t _lambda = 40,
                         std::size_t _k = 1,
                         std::size_t _r = 1,
                         std::size_t _m = 2>
                struct fri_commitment_scheme {
                    static constexpr std::size_t lambda = _lambda;
                    static constexpr std::size_t k = _k;
                    static constexpr std::size_t m = _m;

                    typedef FieldType field_type;
                    typedef Hash transcript_hash_type;

                    typedef typename containers::merkle_tree<Hash, 2> merkle_tree_type;
                    typedef typename containers::merkle_proof<Hash, 2> merkle_proof_type;

                    // static const math::polynomial::polynomial<typename FieldType::value_type>
                    //     q = {0, 0, 1};

                    struct params {

                    };

                    using openning_type = merkle_proof_type;
                    using commitment_type = typename merkle_tree_type::value_type;

                    struct proof_type {
                        
                    };

                    // The result of this function is not commitment_type (as it would expected),
                    // but the built Merkle tree. This is done so, because we often need to reuse
                    // the built Merkle tree
                    // After this function
                    // result.root();
                    // should be called
                    static merkle_tree_type
                        commit(const math::polynomial::polynomial<typename FieldType::value_type> &f,
                               const std::vector<typename FieldType::value_type> &D) {
                    }

                    static proof_type proof_eval(const math::polynomial::polynomial<typename FieldType::value_type> &Q,
                                                 const fiat_shamir_heuristic_updated<transcript_hash_type> &transcript,
                                                 const params &fri_params) {

                        proof_type proof;

                        math::polynomial::polynomial<typename FieldType::value_type> f = Q;

                        typename FieldType::value_type x =
                            transcript.template get_challenge<FieldType>();

                        std::size_t r = fri_params.r;

                        std::array<merkle_proof_type, m *r> &alpha_openings = proof.alpha_openings;
                        std::array<merkle_proof_type, r> &f_y_openings = proof.f_y_openings;
                        std::array<commitment_type, r - 1> &f_commitments = proof.f_commitments;
                        math::polynomial::polynomial<typename FieldType::value_type> &f_ip1_coefficients =
                            proof.f_ip1_coefficients;
                        merkle_tree_type f_round_tree = T;

                        for (std::size_t i = 0; i <= r - 1; i++) {

                            typename FieldType::value_type alpha =
                                transcript.template get_challenge_from<FieldType>(fri_params.D_ip1);

                            typename FieldType::value_type x_next = fri_params.q(x);

                            std::size_t d = f.degree();

                            math::polynomial::polynomial<typename FieldType::value_type> f_next((d + 1)/2 - 1);

                            for (std::size_t index = 0; index < f_next.size(); index++){
                                f_next[index] = f[2*index] + alpha * f[2*index + 1];
                            }

                            // m = 2, so:
                            assert(m == 2);
                            std::array<typename FieldType::value_type, m> s;
                            s[0] = x;
                            s[1] = -x;

                            std::arraytypename FieldType::value_type, m> y;

                            for (std::size_t j = 0; j < m; j++) {
                                y[j] = f(s[j]);
                            }

                            std::array<typename FieldType::value_type, m> p;

                            if (i == 0) {

                                for (std::size_t j = 0; j < m; j++) {

                                    typename FieldType::value_type leaf = f.evaluate(s[j]);
                                    std::size_t leaf_index = std::find(D.begin(), D.end(), leaf) - D.begin();
                                    p[j] = T_0.hash_path(leaf_index);
                                }
                            } else {
                                for (std::size_t j = 0; j < m; j++) {

                                    std::size_t leaf_index = std::find(D.begin(), D.end(), y[j]) - D.begin();
                                    p[j] = T_i.hash_path(leaf_index);
                                }
                            }

                            typename FieldType::value_type f_y_i = f_round.evaluate(y_challenges[i]);
                            std::size_t leaf_index = std::find(D.begin(), D.end(), y_challenges[i]) - D.begin();
                            f_y_openings[i] = merkle_proof_type(f_round_tree, leaf_index);

                            if (i < r - 1) {
                                f_round_tree = commit(f_round, D);
                                f_commitments[i] = f_round_tree.root();
                                transcript(f_commitments[i]);
                            } else {
                                f_ip1_coefficients = f_round;
                            }

                            x = x_next;
                            f = f_next;
                        }

                        return proof;
                    }

                    static bool verify_eval(const std::array<typename FieldType::value_type, k> &evaluation_points,
                                            const commitment_type &root,
                                            const proof_type &proof,
                                            const std::vector<typename FieldType::value_type> &D) {

                        // temporary definition, until polynomial is constexpr
                        const math::polynomial::polynomial<typename FieldType::value_type> q = {0, 0, 1};

                        fiat_shamir_heuristic_updated<transcript_hash_type> transcript;

                        std::array<merkle_proof_type, k> &z_openings = proof.z_openings;
                        std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, k>
                            U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++) {
                            typename FieldType::value_type z_j;
                            // = algebra::marshalling<FieldType>(z_openings[j].leaf);
                            if (!z_openings[j].validate(root)) {
                                return false;
                            }

                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], z_j);
                        }

                        math::polynomial::polynomial<typename FieldType::value_type> U =
                            math::polynomial::lagrange_interpolation(U_interpolation_points);

                        math::polynomial::polynomial<typename FieldType::value_type> Q;
                        // = (f - U);
                        // for (std::size_t j = 0; j < k; j++){
                        //     Q = Q/(x - U_interpolation_points[j]);
                        // }

                        for (std::size_t round_id = 0; round_id < lambda; round_id++) {

                            math::polynomial::polynomial<typename FieldType::value_type> f_i = Q;

                            typename FieldType::value_type x_round =
                                transcript
                                    .template get_challenge<transcript_round_manifest::challenges_ids::x, FieldType>();

                            std::array<merkle_proof_type, m *r> &alpha_openings = proof.alpha_openings[round_id];
                            std::array<merkle_proof_type, r> &f_y_openings = proof.f_y_openings[round_id];
                            std::array<commitment_type, r - 1> &f_commitments = proof.f_commitments[round_id];
                            std::vector<typename FieldType::value_type> &f_ip1_coefficients =
                                proof.f_ip1_coefficients[round_id];

                            commitment_type &f_i_tree_root = root;

                            auto y_arr =
                                transcript.template get_challenges<transcript_round_manifest::challenges_ids::y,
                                                                   r,
                                                                   FieldType>();

                            for (std::size_t i = 0; i <= r - 1; i++) {

                                math::polynomial::polynomial<typename FieldType::value_type> sqr_polynom = {y_arr[i], 0,
                                                                                                            -1};
                                std::array<typename FieldType::value_type, m> s;
                                // = math::polynomial::get_roots<m>(sqr_polynom);

                                std::array<std::pair<typename FieldType::value_type, typename FieldType::value_type>, m>
                                    p_y_i_interpolation_points;

                                for (std::size_t j = 0; j < m; j++) {
                                    typename FieldType::value_type alpha_i_j;
                                    // = algebra::marshalling<FieldType>(alpha_openings[m*i + j].leaf);
                                    if (!alpha_openings[m * i + j].validate(f_i_tree_root)) {
                                        return false;
                                    }
                                    p_y_i_interpolation_points[j] = std::make_pair(s[j], alpha_i_j);
                                }

                                math::polynomial::polynomial<typename FieldType::value_type> p_y_i =
                                    math::polynomial::lagrange_interpolation(p_y_i_interpolation_points);

                                typename FieldType::value_type f_y_i;
                                // = algebra::marshalling<FieldType>(f_y_openings[i].leaf);
                                if (!f_y_openings[i].validate(f_i_tree_root)) {
                                    return false;
                                }

                                if (f_y_i != p_y_i.evaluate(x_round)) {
                                    return false;
                                }

                                x_round = q.evaluate(x_round);

                                if (i < r - 1) {
                                    if (f_i != p_y_i) {
                                        return false;
                                    }

                                    f_commitments[i] = commit(f_i, D).root();
                                    transcript(f_commitments[i]);
                                } else {
                                    if (f_i != p_y_i) {
                                        return false;
                                    }

                                    // if (f_i.size() != ...){
                                    //     return false;
                                    // }
                                }
                            }
                        }
                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP

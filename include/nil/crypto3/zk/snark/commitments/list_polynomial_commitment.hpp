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

#include <nil/crypto3/math/polynomial/polynom.hpp>
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
                template <typename FieldType, typename Hash, std::size_t lambda, std::size_t k, 
                    std::size_t r, std::size_t m=2>
                class list_polynomial_commitment_scheme {

                    typedef Hash transcript_hash_type;

                    typedef typename containers::merkle_tree<Hash, 2> merkle_tree_type;
                    typedef typename containers::merkle_proof<Hash, 2> merkle_proof_type;

                    // static const math::polynomial::polynom<typename FieldType::value_type> 
                    //     q = {0, 0, 1};

                    struct transcript_round_manifest {
                        enum challenges_ids {x, y};
                    };

                public:

                    using openning_type = merkle_proof_type;
                    using commitment_type = typename merkle_tree_type::value_type;

                    struct proof_type {
                        std::array<merkle_proof_type, k> z_openings;
                        std::array<std::array<merkle_proof_type, m * r>, lambda> alpha_openings;
                        std::array<std::array<merkle_proof_type, r>, lambda> f_y_openings;

                        std::array<std::array<commitment_type, r - 1>, lambda> f_commitments;

                        std::array<std::vector<typename FieldType::value_type>, lambda> 
                            f_ip1_coefficients;
                    };

                    // The result of this function is not commitment_type (as it would expected), 
                    // but the built Merkle tree. This is done so, because we often need to reuse 
                    // the built Merkle tree
                    // After this function 
                    // result.root();
                    // should be called
                    static merkle_tree_type commit (const math::polynomial::polynom<
                            typename FieldType::value_type> &f, 
                        const std::vector<typename FieldType::value_type> &D){

                        std::vector<typename FieldType::value_type> y;
                        for (typename FieldType::value_type H : D){
                            y.push_back(f.evaluate(H));
                        }

                        return merkle_tree_type(y);
                    }

                    static proof_type proof_eval (
                        std::array<typename FieldType::value_type, k> evaluation_points, 
                        const merkle_tree_type &T,
                        const math::polynomial::polynom<typename FieldType::value_type> &f, 
                        const std::vector<typename FieldType::value_type> &D){

                        // temporary definition, until polynom is constexpr
                        const math::polynomial::polynom<typename FieldType::value_type> 
                            q = {0, 0, 1};

                        proof_type proof;

                        fiat_shamir_heuristic<transcript_round_manifest, transcript_hash_type> transcript;

                        std::array<merkle_proof_type, k> &z_openings = proof.z_openings;
                        std::array<std::pair<typename FieldType::value_type, 
                            typename FieldType::value_type>, k> U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++){
                            typename FieldType::value_type z_j = 
                                f.evaluate(evaluation_points[j]);
                            std::size_t leaf_index = std::find(D.begin(), D.end(), evaluation_points[j]) - D.begin();
                            z_openings[j] = merkle_proof_type(T, leaf_index);
                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], z_j);
                        }

                        math::polynomial::polynom<typename FieldType::value_type> 
                            U = math::polynomial::lagrange_interpolation(U_interpolation_points);

                        math::polynomial::polynom<typename FieldType::value_type> 
                            Q = (f - U);
                        for (std::size_t j = 0; j < k; j++){
                            math::polynomial::polynom<typename FieldType::value_type> x = {1};
                            Q = Q/(x - U_interpolation_points[j]);
                        }

                        for (std::size_t round_id = 0; round_id < lambda; round_id++){

                            math::polynomial::polynom<typename FieldType::value_type> f_i = Q;

                            typename FieldType::value_type x_i = 
                                transcript.template get_challenge<transcript_round_manifest::challenges_ids::x, FieldType>();

                            std::array<merkle_proof_type, m*r> &alpha_openings = proof.alpha_openings[round_id];
                            std::array<merkle_proof_type, r> &f_y_openings = proof.f_y_openings[round_id];
                            std::array<commitment_type, r - 1> &f_commitments = proof.f_commitments[round_id];
                            std::vector<typename FieldType::value_type> &f_ip1_coefficients = 
                                proof.f_ip1_coefficients[round_id];
                            merkle_tree_type &f_i_tree = T;

                            auto y_arr = 
                                transcript.template get_challenges<transcript_round_manifest::challenges_ids::y, r, FieldType>();

                            for (std::size_t i = 0; i <= r-1; i++){

                                // typename FieldType::value_type y_i = 
                                    // transcript.template get_challenge<transcript_round_manifest::challenges_ids::y, i, FieldType>();

                                math::polynomial::polynom<typename FieldType::value_type> 
                                    sqr_polynom = {y_arr[i], 0, -1};
                                std::array<typename FieldType::value_type, m> s ;
                                    // = math::polynomial::get_roots<m>(sqr_polynom);

                                std::array<std::pair<typename FieldType::value_type, 
                                    typename FieldType::value_type>, m> p_y_i_interpolation_points;


                                for (std::size_t j = 0; j < m; j++){
                                    typename FieldType::value_type alpha_i_j = f_i.evaluate(s[j]);
                                    std::size_t leaf_index = std::find(D.begin(), D.end(), s[j]) - D.begin();
                                    alpha_openings[m*i + j] = merkle_proof_type(f_i_tree, leaf_index);
                                    p_y_i_interpolation_points[j] = std::make_pair(s[j], alpha_i_j);
                                }

                                math::polynomial::polynom<typename FieldType::value_type> 
                                    p_y_i = math::polynomial::lagrange_interpolation(p_y_i_interpolation_points);

                                f_i = p_y_i;

                                typename FieldType::value_type f_y_i = f_i.evaluate(y_arr[i]);
                                std::size_t leaf_index = std::find(D.begin(), D.end(), y_arr[i]) - D.begin();
                                f_y_openings[i] = merkle_proof_type(f_i_tree, leaf_index);

                                x_i = q.evaluate(x_i);

                                if (i < r - 1){
                                    f_i_tree = commit(f_i, D);
                                    f_commitments[i] = f_i_tree.root();
                                    transcript(f_commitments[i]);
                                } else {
                                    f_ip1_coefficients = f_i;
                                }
                            }
                        }

                        return proof;
                    }

                    static bool verify_eval (std::array<typename FieldType::value_type, k> evaluation_points, 
                        commitment_type root,
                        proof_type proof,
                        const std::vector<typename FieldType::value_type> &D){

                        // temporary definition, until polynom is constexpr
                        const math::polynomial::polynom<typename FieldType::value_type> 
                            q = {0, 0, 1};

                        fiat_shamir_heuristic<transcript_round_manifest, transcript_hash_type> transcript;

                        std::array<merkle_proof_type, k> &z_openings = proof.z_openings;
                        std::array<std::pair<typename FieldType::value_type, 
                            typename FieldType::value_type>, k> U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++){
                            typename FieldType::value_type z_j ;
                                // = algebra::marshalling<FieldType>(z_openings[j].leaf);
                            if (!z_openings[j].validate(root)){
                                return false;
                            }

                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], z_j);
                        }

                        math::polynomial::polynom<typename FieldType::value_type> 
                            U = math::polynomial::lagrange_interpolation(U_interpolation_points);

                        math::polynomial::polynom<typename FieldType::value_type> Q ;
                        // = (f - U);
                        // for (std::size_t j = 0; j < k; j++){
                        //     Q = Q/(x - U_interpolation_points[j]);
                        // }

                        for (std::size_t round_id = 0; round_id < lambda; round_id++){

                            math::polynomial::polynom<typename FieldType::value_type> f_i = Q;

                            typename FieldType::value_type x_i = 
                                transcript.template get_challenge<transcript_round_manifest::challenges_ids::x, FieldType>();

                            std::array<merkle_proof_type, m*r> &alpha_openings = proof.alpha_openings[round_id];
                            std::array<merkle_proof_type, r> &f_y_openings = proof.f_y_openings[round_id];
                            std::array<commitment_type, r - 1> &f_commitments = proof.f_commitments[round_id];
                            std::vector<typename FieldType::value_type> &f_ip1_coefficients = 
                                proof.f_ip1_coefficients[round_id];

                            commitment_type &f_i_tree_root = root;

                            auto y_arr = 
                                transcript.template get_challenges<transcript_round_manifest::challenges_ids::y, r, FieldType>();

                            for (std::size_t i = 0; i <= r-1; i++){

                                math::polynomial::polynom<typename FieldType::value_type> sqr_polynom = {y_arr[i], 0, -1};
                                std::array<typename FieldType::value_type, m> s ;
                                    // = math::polynomial::get_roots<m>(sqr_polynom);

                                std::array<std::pair<typename FieldType::value_type, 
                                    typename FieldType::value_type>, m> p_y_i_interpolation_points;

                                for (std::size_t j = 0; j < m; j++){
                                    typename FieldType::value_type alpha_i_j;
                                        // = algebra::marshalling<FieldType>(alpha_openings[m*i + j].leaf);
                                    if (!alpha_openings[m*i + j].validate(f_i_tree_root)){
                                        return false;
                                    }
                                    p_y_i_interpolation_points[j] = std::make_pair(s[j], alpha_i_j);
                                }

                                math::polynomial::polynom<typename FieldType::value_type> 
                                    p_y_i = math::polynomial::lagrange_interpolation(p_y_i_interpolation_points);

                                typename FieldType::value_type f_y_i ;
                                    // = algebra::marshalling<FieldType>(f_y_openings[i].leaf);
                                if (!f_y_openings[i].validate(f_i_tree_root)){
                                    return false;
                                }

                                if (f_y_i != p_y_i.evaluate(x_i)){
                                    return false;
                                }

                                x_i = q.evaluate(x_i);

                                if (i < r - 1){
                                    if (f_i != p_y_i){
                                        return false;
                                    }

                                    f_commitments[i] = commit(f_i, D).root();
                                    transcript(f_commitments[i]);
                                } else {
                                    if (f_i != p_y_i){
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

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

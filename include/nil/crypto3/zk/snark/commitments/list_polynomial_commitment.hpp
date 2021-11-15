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

#include <nil/crypto3/zk/snark/commitments/commitment.hpp>

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
                template <typename FieldType, typename Hash>
                class list_polynomial_commitment_scheme {

                    typedef typename merkletree::MerkleTree<Hash> merkle_tree_type;
                    typedef typename merkletree::MerkleProof<Hash> merkle_proof_type;

                    constexpr static const math::polynom<...> q = {0, 0, 1};

                    struct transcript_round_manifest {
                        enum challenges_ids {x, y};
                    }
                public:

                    using openning_type = merkle_proof_type;
                    using commitment_type = typename merkle_tree_type::root_type;

                    template <std::size_t k, std::size_t lambda, std::size_t r>
                    struct proof_type {
                        std::array<merkle_proof_type, k> z_openings;
                        std::array<std::array<merkle_proof_type, 2 * r>, lamda> alpha_openings;

                        std::array<std::array<commitment_type, r - 1>, lamda> f_commitments;

                        std::array<std::array<...>, lambda> f_ip1_coefficients;
                    }

                    // The result of this function is not commitment_type (as it would expected), 
                    // but the built Merkle tree. This is done so, because we often need to reuse 
                    // the built Merkle tree
                    // After this function 
                    // result.root();
                    // should be called
                    template <...>
                    static merkle_tree_type commit (const math::polynom<...> &f, 
                        const std::vector<...> &D){

                        std::vector<...> y;
                        for (... H : D){
                            y.push_back(f.evaluate(H));
                        }

                        return merkle_tree_type(y);
                    }

                    template <std::size_t lambda, std::size_t k>
                    static ... proof_eval (std::array<..., k> evaluation_points, 
                        const merkle_tree_type &T,
                        const math::polynom<...> &f, 
                        const std::vector<...> &D){

                        proof_type proof;

                        fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> transcript;

                        std::array<merkle_proof_type, k> &z_openings = proof.z_openings;
                        std::array<std::pair<..., ...>, k> U_interpolation_points;

                        for (std::size_t j = 0; j < k; j++){
                            ... z_j = f.evaluate(evaluation_points[j]);
                            std::size_t leaf_index = std::find(D.begin(), D.end(), evaluation_points[j]) - D.begin();
                            z_openings[j] = merkle_proof_type(T, leaf_index);
                            U_interpolation_points[j] = std::make_pair(evaluation_points[j], z_j);
                        }

                        math::polynom<...> U = math::polynomial::Lagrange_interpolation(U_interpolation_points);

                        math::polynom<...> Q = (f - U);
                        for (std::size_t j = 0; j < k; j++){
                            Q = Q/(x - U_interpolation_points[j]);
                        }

                        for (std::size_t round_id = 0; round_id < lambda; round_id++){

                            math::polynom<...> f_i = Q;

                            ... x_i = transcript.get_challenge<transcript_manifest::challenges_ids::x>();

                            std::array<merkle_proof_type, 2*r> &alpha_openings = proof.alpha_openings[round_id];
                            std::array<commitment_type, r - 1> &f_commitments = proof.f_commitments[round_id];
                            std::array<...> &f_ip1_coefficients = proof.f_ip1_coefficients[round_id];

                            for (std::size_t i = 0; i <= r-1; i++){

                                ... y_i = transcript.get_challenge<transcript_manifest::challenges_ids::y, i>();

                                math::polynom<...> sqr_polynom = {y_i, 0, -1};
                                std::array<..., 2> s = math::polynomial::get_roots<2>(sqr_polynom);

                                std::array<std::pair<..., ...>, 2> p_i_j_interpolation_points;

                                for (std::size_t j = 0; j < 2; j++){
                                    ... alpha_i_j = f_i.evaluate(s[j]);
                                    std::size_t leaf_index = std::find(D.begin(), D.end(), s[j]) - D.begin();
                                    alpha_openings[2*i + j] = merkle_proof_type(T, leaf_index);
                                    p_i_j_interpolation_points[j] = std::make_pair(s[j], alpha_i_j);
                                }

                                math::polynom<...> p_i_j = math::polynomial::Lagrange_interpolation(p_i_j_interpolation_points);

                                f_i = p_i_j;

                                x = q.evaluate(x);

                                if (i < r - 1){
                                    f_commitments[i] = commit(f_i, D_ip1).root();
                                } else {
                                    f_ip1_coefficients = math::polynomial::get_coefficients(f_i);
                                }
                            }
                        }

                        return proof;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP

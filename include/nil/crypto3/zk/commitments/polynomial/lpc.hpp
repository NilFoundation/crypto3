//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
//#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                
                template<typename MerkleTreeHashType, typename TranscriptHashType, std::size_t Lambda,
                         std::size_t R, std::size_t M, std::size_t BatchesNum>
                struct list_polynomial_commitment_params {
                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t lambda = Lambda;
                    constexpr static const std::size_t r = R;
                    constexpr static const std::size_t m = M;
                    constexpr static const std::size_t batches_num = BatchesNum;
                };
                /**
                 * @brief Based on the FRI Commitment description from \[RedShift].
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
                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment;

                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment: public detail::basic_batched_fri<
                        FieldType, 
                        typename LPCParams::merkle_hash_type,
                        typename LPCParams::transcript_hash_type,
                        LPCParams::lambda, 
                        LPCParams::m,
                        LPCParams::batches_num
                > {

                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t r = LPCParams::r;
                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const std::size_t batches_num = LPCParams::batches_num;
                    constexpr static const bool is_const_size = LPCParams::is_const_size;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using basic_fri = detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                        typename LPCParams::transcript_hash_type,
                        LPCParams::lambda, LPCParams::m, LPCParams::batches_num
                    >;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;
                    using field_type = FieldType;
                    using polynomials_values_type = typename basic_fri::polynomials_values_type;
                    using params_type = typename basic_fri::params_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return fri_proof == rhs.fri_proof && z == rhs.z;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }
                        typedef std::vector<std::vector<typename FieldType::value_type>> z_type;

                        std::array<z_type, batches_num> z;
                        typename basic_fri::proof_type fri_proof;
                    };
                };

                template<typename FieldType, typename LPCParams>
                using batched_lpc = batched_list_polynomial_commitment<
                    FieldType, commitments::list_polynomial_commitment_params<
                        typename LPCParams::merkle_hash_type, typename LPCParams::transcript_hash_type,
                        LPCParams::lambda, LPCParams::r,  LPCParams::m, LPCParams::batches_num
                    >>;
                template<typename FieldType, typename LPCParams>
                using lpc = batched_list_polynomial_commitment<
                    FieldType, list_polynomial_commitment_params<
                        typename LPCParams::merkle_hash_type, typename LPCParams::transcript_hash_type,
                        LPCParams::lambda, LPCParams::r,  LPCParams::m, LPCParams::batches_num
                    >>;

                template<typename FieldType, typename LPCParams>
                using list_polynomial_commitment = batched_list_polynomial_commitment<FieldType, LPCParams>;

            }    // namespace commitments

            namespace algorithms {
                template<
                    typename LPC,
                    typename ContainerType,    // TODO: check for value_type == std::vector<typename
                                               // LPC::field_type::value_type>?
                    typename std::enable_if<std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                            typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value &&
                                                std::is_same_v<typename ContainerType::value_type,
                                                               std::vector<typename LPC::field_type::value_type>>,
                                            bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    const std::array<ContainerType, LPC::basic_fri::batches_num> &evaluation_points,
                    const std::array<typename LPC::precommitment_type, LPC::basic_fri::batches_num> &precommitments,
                    std::array<std::vector<math::polynomial<typename LPC::field_type::value_type>>, LPC::basic_fri::batches_num> &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()
                ) {
                    for(std::size_t i = 0; i < LPC::basic_fri::batches_num; i++) {
                        transcript(commit<typename LPC::basic_fri>(precommitments[i]));
                    }
                    typename LPC::field_type::value_type theta = transcript.template challenge<typename LPC::field_type>();
                    math::polynomial<typename LPC::field_type::value_type> combined_Q;
                    std::array<typename LPC::proof_type::z_type, LPC::basic_fri::batches_num> z;

                    math::polynomial<typename LPC::field_type::value_type> combined_U = {0};
                    for (std::size_t k = 0; k < LPC::basic_fri::batches_num; k++) {
                        z[k].resize(g[k].size());
                        for (std::size_t polynom_index = 0; polynom_index < g[k].size(); polynom_index++) {
                            auto evaluation_point = evaluation_points[k][0];
                            if (polynom_index < evaluation_points[k].size()) {
                                evaluation_point = evaluation_points[k][polynom_index];
                            }

                            std::vector<std::pair<typename LPC::field_type::value_type, typename LPC::field_type::value_type>> U_interpolation_points;
                            U_interpolation_points.resize(evaluation_point.size());
                            z[k][polynom_index].resize(evaluation_point.size());

                            for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {

                                z[k][polynom_index][point_index] = g[k][polynom_index].evaluate(
                                    evaluation_point[point_index]);    // transform to point-representation

                                U_interpolation_points[point_index] =
                                    std::make_pair(evaluation_point[point_index],
                                                z[k][polynom_index][point_index]);    // prepare points for interpolation
                            }

                            math::polynomial<typename LPC::field_type::value_type> Q;
                            math::polynomial<typename LPC::field_type::value_type> U = math::lagrange_interpolation(U_interpolation_points);

                            Q = g[k][polynom_index] - U;
                            combined_U = combined_U * theta;
                            combined_U = combined_U + U;

                            math::polynomial<typename LPC::field_type::value_type> denominator_polynom = {1};
                            for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {
                                denominator_polynom =
                                    denominator_polynom * math::polynomial<typename LPC::field_type::value_type> {
                                                            -evaluation_point[point_index], 1};
                            }

                            Q = Q / denominator_polynom;
                            if (k == 0 && polynom_index == 0) {
                                combined_Q = Q;
                            } else {
                                combined_Q = combined_Q * theta + Q;
                            }
                        }
                    }
                    typename LPC::basic_fri::proof_type fri_proof;
                    typename LPC::precommitment_type combined_Q_precommitment =
                    precommit<typename LPC::basic_fri>(combined_Q, fri_params.D[0], fri_params.step_list.front());

                    fri_proof = proof_eval<typename LPC::basic_fri, math::polynomial<typename LPC::field_type::value_type>>(
                            g,
                            combined_Q, 
                            precommitments,
                            combined_Q_precommitment, 
                            fri_params, 
                            transcript
                    );
                    return typename LPC::proof_type({z, fri_proof});
                }

                template<typename LPC, typename std::enable_if<
                                            std::is_base_of<commitments::batched_list_polynomial_commitment<
                                                                typename LPC::field_type, typename LPC::lpc_params>,
                                                            LPC>::value,
                                            bool>::type = true>
                static typename LPC::proof_type proof_eval(
                    std::array<std::vector<std::vector<typename LPC::field_type::value_type>>, LPC::basic_fri::batches_num> &evaluation_points,
                    const std::array<typename LPC::precommitment_type, LPC::basic_fri::batches_num> &precommitments,
                    std::array<std::vector<math::polynomial_dfs<typename LPC::field_type::value_type>>, LPC::basic_fri::batches_num> &g,
                    const typename LPC::basic_fri::params_type &fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()
                ) {
                    for(std::size_t i = 0; i < LPC::basic_fri::batches_num; i++) {
                        transcript(commit<typename LPC::basic_fri>(precommitments[i]));
                    }
                    
                    // Prepare z-s and combined_Q;
                    typename LPC::field_type::value_type theta = transcript.template challenge<typename LPC::field_type>();
                    math::polynomial_dfs<typename LPC::field_type::value_type> combined_Q_dfs(
                        0, fri_params.D[0]->size(), 
                        LPC::field_type::value_type::zero()
                    );


                    std::array<typename LPC::proof_type::z_type, LPC::basic_fri::batches_num> z;
                    
                    for (std::size_t k = 0; k < LPC::basic_fri::batches_num; k++) {
                        z[k].resize(g[k].size());

                        // Prepare U_interpolation_points and denominator_polynom
                        for (std::size_t polynom_index = 0; polynom_index < g[k].size(); polynom_index++) {
                            // Logic: Complex and different evaluation points may be only for the first polys in the batch. 
                            // TODO : handle the case when only one evaluation_point. And not allow a
                            auto evaluation_point = evaluation_points[k][0];
                            if (polynom_index < evaluation_points[k].size()) {
                                evaluation_point = evaluation_points[k][polynom_index];
                            }

                            // It's simple: list of {key, value} pairs
                            std::vector<std::pair<typename LPC::field_type::value_type, typename LPC::field_type::value_type>> U_interpolation_points;

                            U_interpolation_points.resize(evaluation_point.size());
                            z[k][polynom_index].resize(evaluation_point.size());

                            math::polynomial<typename LPC::field_type::value_type> g_normal(g[k][polynom_index].coefficients());

                            math::polynomial<typename LPC::field_type::value_type> V = {1};
                            for (std::size_t point_index = 0; point_index < evaluation_point.size(); point_index++) {
                                z[k][polynom_index][point_index] = g_normal.evaluate(evaluation_point[point_index]);
                                U_interpolation_points[point_index] =
                                    std::make_pair(evaluation_point[point_index],
                                        z[k][polynom_index][point_index]
                                );    // prepare points for interpolation
                                V = V * math::polynomial<typename LPC::field_type::value_type>({-evaluation_point[point_index],1});
                            }
                            math::polynomial<typename LPC::field_type::value_type> U =
                                math::lagrange_interpolation(U_interpolation_points);
                            math::polynomial_dfs<typename LPC::field_type::value_type> U_dfs(0, fri_params.D[0]->size());
                            U_dfs.from_coefficients(U);
                            math::polynomial_dfs<typename LPC::field_type::value_type> denominator_dfs(0, fri_params.D[0]->size());

                            math::polynomial<typename LPC::field_type::value_type> Q = g_normal - U;
                            Q = Q / V;
                            math::polynomial_dfs<typename LPC::field_type::value_type> Q_dfs(0, fri_params.D[0]->size());
                            Q_dfs.from_coefficients(Q);

                            if (k == 0 && polynom_index == 0) {
                                combined_Q_dfs = Q_dfs;
                            } else {
                                combined_Q_dfs *= theta;
                                combined_Q_dfs += Q_dfs;
                            }
                        }
                    }

                    typename LPC::basic_fri::proof_type fri_proof;
                    typename LPC::precommitment_type combined_Q_precommitment = precommit<typename LPC::basic_fri>(
                        combined_Q_dfs, 
                        fri_params.D[0], 
                        fri_params.step_list.front()
                    );

                    fri_proof = proof_eval<typename LPC::basic_fri, math::polynomial_dfs<typename LPC::field_type::value_type>>(
                        g,
                        combined_Q_dfs, 
                        precommitments,
                        combined_Q_precommitment, 
                        fri_params, 
                        transcript
                    );
                    return typename LPC::proof_type({z, fri_proof});
                }

                template<
                    typename LPC
                >
                static bool verify_eval(
                    const std::array<std::vector<std::vector<typename LPC::field_type::value_type>>, LPC::basic_fri::batches_num> &evaluation_points,
                    typename LPC::proof_type &proof,
                    const std::array<typename LPC::commitment_type, LPC::basic_fri::batches_num> &commitments,
                    typename LPC::basic_fri::params_type fri_params,
                    typename LPC::basic_fri::transcript_type &transcript = typename LPC::basic_fri::transcript_type()
                ) {
                    for( std::size_t k = 0; k < LPC::basic_fri::batches_num; k++){
                        transcript(commitments[k]);
                    }

                    typename std::vector<std::size_t> evals_map;
                    typename std::vector<std::vector<typename LPC::field_type::value_type>> unique_eval_points;
                    typename std::vector<math::polynomial<typename LPC::field_type::value_type>> combined_U;
                    typename std::vector<math::polynomial<typename LPC::field_type::value_type>> denominators;
                    typename LPC::field_type::value_type theta = transcript.template challenge<typename LPC::field_type>();

                    std::size_t batch_size = 0;
                    for( std::size_t k = 0; k < LPC::basic_fri::batches_num; k++){
                        BOOST_ASSERT( evaluation_points[k].size() == proof.z[k].size() || evaluation_points[k].size() == 1);
                        batch_size += proof.z[k].size();
                    }
                    evals_map.resize(batch_size);

                    std::size_t ind = 0;
                    bool found = false;
                    for( std::size_t k = 0; k < LPC::basic_fri::batches_num; k++){
                        if( evaluation_points[k].size() == 1) {
                            bool found = false;
                            std::size_t eval_ind;

                            for( std::size_t j = 0; j < unique_eval_points.size(); j++ ){
                                if( unique_eval_points[j] == evaluation_points[k][0] ){
                                    found = true;
                                    eval_ind = j;
                                    break;
                                }
                            }
                            if( !found ){
                                unique_eval_points.push_back(evaluation_points[k][0]);
                                eval_ind = unique_eval_points.size() - 1; 
                            }
                            for( std::size_t i = 0; i < proof.z[k].size(); i++ ){
                                BOOST_ASSERT(proof.z[k][i].size() == unique_eval_points[eval_ind].size());
                                evals_map[ind] = eval_ind;
                                ind++;
                            }
                        } else {
                            for( std::size_t i = 0; i < proof.z[k].size(); i++ ){
                                bool found = false;
                                BOOST_ASSERT(proof.z[k][i].size() == evaluation_points[k][i].size());
                                for( std::size_t j = 0; j < unique_eval_points.size(); j++ ){
                                    if( unique_eval_points[j] == evaluation_points[k][i] ){
                                        evals_map[ind] = j;
                                        found = true;
                                        break;
                                    }
                                }
                                if( !found ){
                                    unique_eval_points.push_back(evaluation_points[k][i]);
                                    evals_map[ind] = unique_eval_points.size() - 1; 
                                }
                                ind++;
                            }
                        }
                    }

                    combined_U.resize(unique_eval_points.size());
                    denominators.resize(unique_eval_points.size());
                    for(std::size_t point_index = 0; point_index < unique_eval_points.size(); point_index++ ){
                        combined_U[point_index] = {0};
                        denominators[point_index] = {1};
                        std::vector<
                            std::pair<typename LPC::field_type::value_type, typename LPC::field_type::value_type>
                        > U_interpolation_points;

                        U_interpolation_points.resize(unique_eval_points[point_index].size());
                        for( std::size_t xi_index = 0; xi_index < unique_eval_points[point_index].size(); xi_index++ ){
                            denominators[point_index] = 
                                denominators[point_index] * 
                                math::polynomial<typename LPC::field_type::value_type>({-unique_eval_points[point_index][xi_index], 1});
                        }

                        std::size_t ind = 0;
                        for( std::size_t k = 0; k < LPC::basic_fri::batches_num; k++){
                            for( std::size_t i = 0; i < proof.z[k].size(); i++ ){
                                combined_U[point_index] = combined_U[point_index] * theta;
                                if(evals_map[ind] == point_index){
                                    BOOST_ASSERT(proof.z[k][i].size() == unique_eval_points[point_index].size());
                                    for( std::size_t xi_index = 0; xi_index < unique_eval_points[point_index].size(); xi_index++ ){
                                        U_interpolation_points[xi_index] = std::make_pair(
                                            unique_eval_points[point_index][xi_index],
                                            proof.z[k][i][xi_index]
                                        );
                                    }
                                    math::polynomial<typename LPC::field_type::value_type> U = math::lagrange_interpolation(U_interpolation_points);
                                    combined_U[point_index] = combined_U[point_index] + math::lagrange_interpolation(U_interpolation_points);
                                }
                                ind++;
                            }
                        }
                    }

                    if (!verify_eval<typename LPC::basic_fri>(
                        proof.fri_proof,
                        fri_params, 
                        commitments,
                        theta,
                        evals_map,
                        combined_U,
                        denominators,
                        transcript
                    )) {
                        return false;
                    }
                    return true;
                }

            }    // namespace algorithms
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

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
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                // Placeholder-friendly class.
                template<typename LPCScheme, typename PolynomialType = typename math::polynomial_dfs<
                    typename LPCScheme::params_type::field_type::value_type>>
                class lpc_commitment_scheme : public polys_evaluator<typename LPCScheme::params_type,
                    typename LPCScheme::commitment_type, PolynomialType>{

                public:
                    using field_type = typename LPCScheme::field_type;
                    using value_type = typename field_type::value_type;
                    using params_type = typename LPCScheme::params_type;
                    using precommitment_type = typename LPCScheme::precommitment_type;
                    using commitment_type = typename LPCScheme::commitment_type;
                    using fri_type = typename LPCScheme::fri_type;
                    using basic_fri = typename LPCScheme::fri_type;
                    using proof_type = typename LPCScheme::proof_type;
                    using transcript_type = typename LPCScheme::transcript_type;
                    using transcript_hash_type = typename LPCScheme::transcript_hash_type;
                    using poly_type = PolynomialType;
                    using lpc = LPCScheme;
                    using eval_storage_type = typename LPCScheme::eval_storage_type;
                    using preprocessed_data_type = std::map<std::size_t, std::vector<value_type>>;

                private:
                    std::map<std::size_t, precommitment_type> _trees;
                    typename fri_type::params_type _fri_params;
                    value_type _etha;
                    std::map<std::size_t, bool> _batch_fixed;
                    preprocessed_data_type _fixed_polys_values;

                public:
                    lpc_commitment_scheme(const typename fri_type::params_type &fri_params)
                        : _fri_params(fri_params), _etha(0) {
                    }

                    preprocessed_data_type preprocess(transcript_type& transcript) const{
                        auto etha = transcript.template challenge<field_type>();

                        preprocessed_data_type result;
                        for(auto const&[index, fixed]: _batch_fixed) {
                            if(!fixed) continue;
                            result[index] = {};
                            for (const auto& poly: this->_polys.at(index)){
                                result[index].push_back(poly.evaluate(etha));
                            }
                        }
                        return result;
                    }

                    void setup(transcript_type& transcript, const preprocessed_data_type &preprocessed_data) {
                        _etha = transcript.template challenge<field_type>();
                        _fixed_polys_values = preprocessed_data;
                    }

                    commitment_type commit(std::size_t index) {
                        this->state_commited(index);
                        _trees[index] = nil::crypto3::zk::algorithms::precommit<fri_type>(
                            this->_polys[index], _fri_params.D[0], _fri_params.step_list.front());
                        return _trees[index].root();
                    }

                    // Should be done after commitment.
                    void mark_batch_as_fixed(std::size_t index) {
                        _batch_fixed[index] = true;
                    }

                    proof_type proof_eval(transcript_type &transcript) {
                        for (auto const& it: _batch_fixed) {
                            if (it.second) {
                                this->append_eval_point(it.first, _etha);
                            }
                        }

                        this->eval_polys();

                        BOOST_ASSERT(this->_points.size() == this->_polys.size());
                        BOOST_ASSERT(this->_points.size() == this->_z.get_batches_num());

                        for(auto const& it: this->_trees) {
                            transcript(it.second.root());
                        }

                        // Prepare z-s and combined_Q;
                        auto theta = transcript.template challenge<field_type>();
                        typename field_type::value_type theta_acc(1);
                        poly_type combined_Q;
                        math::polynomial<value_type> V;

                        auto points = this->get_unique_points();
                        math::polynomial<value_type> combined_Q_normal;

                        for (auto const &point: points){
                            V = {-point, 1};
                            math::polynomial<value_type> Q_normal;
                            for(std::size_t i: this->_z.get_batches()){
                                for(std::size_t j = 0; j < this->_z.get_batch_size(i); j++){
                                    auto it = std::find(this->_points[i][j].begin(), this->_points[i][j].end(), point);
                                    if( it == this->_points[i][j].end()) continue;
                                    math::polynomial<value_type> g_normal;
                                    if constexpr(std::is_same<math::polynomial_dfs<value_type>, PolynomialType>::value ) {
                                        g_normal = math::polynomial<value_type>(this->_polys[i][j].coefficients());
                                    } else {
                                        g_normal = this->_polys[i][j];
                                    }
                                    g_normal *= theta_acc;
                                    Q_normal += g_normal;
                                    Q_normal -= this->_z.get(i, j, it - this->_points[i][j].begin()) * theta_acc;
                                    theta_acc *= theta;
                                }
                            }
                            Q_normal = Q_normal / V;
                            combined_Q_normal += Q_normal;
                        }

                        if constexpr (std::is_same<math::polynomial_dfs<value_type>, PolynomialType>::value ) {
                            combined_Q.from_coefficients(combined_Q_normal);
                        } else {
                            combined_Q = combined_Q_normal;
                        }

                        precommitment_type combined_Q_precommitment = nil::crypto3::zk::algorithms::precommit<fri_type>(
                            combined_Q,
                            _fri_params.D[0],
                            _fri_params.step_list.front()
                        );

                        typename fri_type::proof_type fri_proof = nil::crypto3::zk::algorithms::proof_eval<
                            fri_type, poly_type
                        >(
                            this->_polys,
                            combined_Q,
                            this->_trees,
                            combined_Q_precommitment,
                            this->_fri_params,
                            transcript
                        );
                        return proof_type({this->_z, fri_proof});
                    }

                    bool verify_eval(
                        const proof_type &proof,
                        const std::map<std::size_t, commitment_type> &commitments,
                        transcript_type &transcript
                    ) {
                        for (auto const&[b_ind, fixed]: _batch_fixed) {
                            if(!fixed) continue;
                            this->append_eval_point(b_ind, _etha);
                            for( std::size_t i = 0; i < proof.z.get_batch_size(b_ind); i++) {
                                if(this->_fixed_polys_values[b_ind][i] != proof.z.get(b_ind, i, proof.z.get_poly_points_number(b_ind, i) - 1)) {
                                    return false;
                                }
                            }
                        }

                        this->_z = proof.z;
                        for (auto const &it: commitments) {
                            transcript(commitments.at(it.first));
                        }

                        auto points = this->get_unique_points();
                        // List of unique eval points set. [id=>points]
                        typename std::vector<typename field_type::value_type> U(points.size());
                        // V is product of (x - eval_point) polynomial for each eval_point
                        typename std::vector<math::polynomial<value_type>> V(points.size());
                        // List of involved polynomials for each eval point [batch_id, poly_id, point_id]
                        typename std::vector<std::vector<std::tuple<std::size_t, std::size_t>>> poly_map(points.size());

                        value_type theta = transcript.template challenge<field_type>();
                        value_type theta_acc(1);

                        for (std::size_t p = 0; p < points.size(); p++){
                            auto &point = points[p];
                            V[p] = {-point, 1};
                            for(std::size_t i:this->_z.get_batches()){
                                for(std::size_t j = 0; j < this->_z.get_batch_size(i); j++){
                                    auto it = std::find(this->_points[i][j].begin(), this->_points[i][j].end(), point);
                                    if( it == this->_points[i][j].end()) continue;
                                    U[p] += this->_z.get(i, j, it - this->_points[i][j].begin()) * theta_acc;
                                    poly_map[p].push_back(std::make_tuple(i, j));
                                    theta_acc *= theta;
                                }
                            }
                        }

                        if (!nil::crypto3::zk::algorithms::verify_eval<fri_type>(
                            proof.fri_proof,
                            _fri_params,
                            commitments,
                            theta,
                            poly_map,
                            U,
                            V,
                            transcript
                        )) {
                            return false;
                        }
                        return true;
                    }

                    // Params for LPC are actually FRI params. We can return some LPC params from here in the future if needed.
                    // This params are used for initializing transcript in the prover.
                    const params_type& get_commitment_params() const {
                        return _fri_params;
                    }

                    boost::property_tree::ptree get_params() const{
                        boost::property_tree::ptree params;
                        params.put("type", "LPC");
                        params.put("r", _fri_params.r);
                        params.put("m", fri_type::m);
                        params.put("lambda", fri_type::lambda);
                        params.put("max_degree", _fri_params.max_degree);

                        boost::property_tree::ptree step_list_node;
                        for( std::size_t j = 0; j < _fri_params.step_list.size(); j++){
                            boost::property_tree::ptree step_node;
                            step_node.put("", _fri_params.step_list[j]);
                            step_list_node.push_back(std::make_pair("", step_node));
                        }
                        params.add_child("step_list", step_list_node);

                        boost::property_tree::ptree D_omegas_node;
                        for(std::size_t j = 0; j < _fri_params.D.size(); j++){
                            boost::property_tree::ptree D_omega_node;
                            D_omega_node.put("", _fri_params.D[j]->get_domain_element(1));
                            D_omegas_node.push_back(std::make_pair("", D_omega_node));
                        }
                        params.add_child("D_omegas", D_omegas_node);

                        if( fri_type::use_grinding ){
                            params.add_child("grinding_params", fri_type::grinding_type::get_params());
                        }
                        return params;
                    }
                };

                template<typename MerkleTreeHashType, typename TranscriptHashType, std::size_t Lambda,
                        std::size_t M, bool UseGrinding = false, typename GrindingType = proof_of_work<TranscriptHashType>>
                struct list_polynomial_commitment_params {
                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t lambda = Lambda;
                    constexpr static const std::size_t m = M;
                    constexpr static const bool use_grinding = UseGrinding;
                    typedef GrindingType grinding_type;
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
                struct batched_list_polynomial_commitment : public detail::basic_batched_fri<
                    FieldType,
                    typename LPCParams::merkle_hash_type,
                    typename LPCParams::transcript_hash_type,
                    LPCParams::lambda,
                    LPCParams::m,
                    LPCParams::use_grinding,
                    typename LPCParams::grinding_type
                > {
                    using fri_type = typename detail::basic_batched_fri<
                        FieldType,
                        typename LPCParams::merkle_hash_type,
                        typename LPCParams::transcript_hash_type,
                        LPCParams::lambda,
                        LPCParams::m,
                        LPCParams::use_grinding,
                        typename LPCParams::grinding_type
                    >;
                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const bool is_const_size = LPCParams::is_const_size;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using basic_fri = detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                            typename LPCParams::transcript_hash_type,
                            LPCParams::lambda, LPCParams::m,
                            LPCParams::use_grinding, typename LPCParams::grinding_type>;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;
                    using field_type = FieldType;
                    using polynomials_values_type = typename basic_fri::polynomials_values_type;
                    using params_type = typename basic_fri::params_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<typename LPCParams::transcript_hash_type>;
                    using transcript_hash_type = typename LPCParams::transcript_hash_type;
                    using eval_storage_type = eval_storage<field_type>;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return fri_proof == rhs.fri_proof && z == rhs.z;
                        }

                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        eval_storage_type z;
                        typename basic_fri::proof_type fri_proof;
                    };
                };

                template<typename FieldType, typename LPCParams>
                using batched_lpc = batched_list_polynomial_commitment<
                        FieldType, commitments::list_polynomial_commitment_params<
                                typename LPCParams::merkle_hash_type, typename LPCParams::transcript_hash_type,
                                LPCParams::lambda, LPCParams::m,
                                LPCParams::use_grinding, typename LPCParams::grinding_type
                        >>;
                template<typename FieldType, typename LPCParams>
                using lpc = batched_list_polynomial_commitment<
                        FieldType, list_polynomial_commitment_params<
                                typename LPCParams::merkle_hash_type, typename LPCParams::transcript_hash_type,
                                LPCParams::lambda, LPCParams::m,
                                LPCParams::use_grinding, typename LPCParams::grinding_type
                        >>;

                template<typename FieldType, typename LPCParams>
                using list_polynomial_commitment = batched_list_polynomial_commitment<FieldType, LPCParams>;
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

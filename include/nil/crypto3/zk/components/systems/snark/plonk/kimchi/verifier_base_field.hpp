//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the BASE_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_BASE_FIELD_HPP
#define CRYPTO3_ZK_BLUEPRINT_BASE_FIELD_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
//#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/commitment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/map_fq.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // base field part of batch_verify
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L911
                // Input: list of mina-proofs (base field part),
                //     precalculated fq_data and fr_data (the data that used both by scalar and base verifiers)
                //     verifier index (public data)
                // Output: - 
                template<typename ArithmetizationType, typename CurveType,
                typename KimchiParamsType, typename KimchiCommitmentParamsType, std::size_t BatchSize,
                std::size_t n, std::size_t size, std::size_t bases_size, std::size_t max_unshifted_size, std::size_t proof_len, std::size_t lagrange_bases_size,
                         std::size_t... WireIndexes>
                class base_field;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType,
                         std::size_t BatchSize,
                         std::size_t n,
                         std::size_t size,
                         std::size_t bases_size,
                         std::size_t max_unshifted_size,
                         std::size_t proof_len,
                         std::size_t lagrange_bases_size,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class base_field<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       CurveType,
                                                       KimchiParamsType,
                                                       KimchiCommitmentParamsType,
                                                       BatchSize,
                                                       n,
                                                        size,
                                                        bases_size,
                                                        max_unshifted_size,
                                                        proof_len,
                                                        lagrange_bases_size,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8,
                                                       W9,
                                                       W10,
                                                       W11,
                                                       W12,
                                                       W13,
                                                       W14 > {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;
                    

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using const_mul_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;

                    using msm_component = zk::components::element_g1_multi_scalar_mul< ArithmetizationType, CurveType, size,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using lagrange_msm_component = zk::components::element_g1_multi_scalar_mul< ArithmetizationType, CurveType, lagrange_bases_size,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> ;

                    using scalar_mul_component =
                        zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    using add_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                                       W4, W5, W6, W7, W8, W9, W10>;
                    using batch_verify_component =
                        zk::components::batch_verify_base_field<ArithmetizationType, CurveType, 
                                            KimchiParamsType, KimchiCommitmentParamsType, n, bases_size, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;

                    using proof_binding = typename zk::components::binding<ArithmetizationType,
                        BlueprintFieldType, KimchiCommitmentParamsType>;

                    using map_fq_component = zk::components::map_fq<ArithmetizationType, 
                        CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize,
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using shifted_commitment_type = typename 
                        zk::components::kimchi_shifted_commitment_type<BlueprintFieldType, 
                            KimchiCommitmentParamsType::shifted_commitment_split>;

                    using opening_proof_type = typename 
                        zk::components::kimchi_opening_proof<BlueprintFieldType, KimchiCommitmentParamsType::eval_rounds>;

                    using batch_proof_type = typename 
                        zk::components::batch_evaluation_proof_base<BlueprintFieldType, 
                            ArithmetizationType, KimchiParamsType,
                            KimchiCommitmentParamsType>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType,
                        KimchiCommitmentParamsType>;

                    constexpr static const std::size_t selector_seed = 0xff91;

                public:
                    constexpr static const std::size_t rows_amount = (1 + (2 + 2*max_unshifted_size) * (scalar_mul_component::rows_amount + add_component::rows_amount) 
                    + (max_unshifted_size + 1)*msm_component::rows_amount + lagrange_msm_component::rows_amount + 2 * const_mul_component::rows_amount + batch_verify_component::rows_amount) * proof_len;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {

                        struct commitments {
                             std::vector<shifted_commitment_type> witness_comm;
                             std::vector<shifted_commitment_type> sigma_comm;
                             std::vector<shifted_commitment_type> coefficient_comm;
                             std::vector<shifted_commitment_type> oracles_poly_comm; // to-do: get in the component from oracles
                             shifted_commitment_type lookup_runtime_comm;
                             shifted_commitment_type table_comm;
                             std::vector<shifted_commitment_type> lookup_sorted_comm;
                             std::vector<shifted_commitment_type> lookup_selectors_comm;
                             std::vector<shifted_commitment_type> selectors_comm;
                             shifted_commitment_type lookup_agg_comm;
                             shifted_commitment_type z_comm;
                             shifted_commitment_type t_comm;
                             shifted_commitment_type generic_comm;
                             shifted_commitment_type psm_comm;
                        };
                        struct var_proof {
                            commitments comm;
                            opening_proof_type o;
                            std::vector<var> scalars;
                        };
                        struct public_input {
                            std::vector<var_ec_point> lagrange_bases;
                            std::vector<var> neg_pub;
                            var zeta_to_srs_len;
                            var zeta_to_domain_size_minus_1;
                            std::vector<var> cip;
                        };
                        struct result {
                            std::vector<var_proof> proofs;
                            verifier_index_type verifier_index;
                            public_input PI;
                        };

                        typename proof_binding::fr_data<var> fr_data;
                        typename proof_binding::fq_data<var> fq_data;

                        result input;  
                    };

                    struct result_type {

                        result_type(std::size_t component_start_row) {
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        std::size_t p_size = params.input.proofs.size();
                        std::vector<typename batch_verify_component::params_type::var_proof> batch_proofs;
                        for(std::size_t i = 0; i < p_size; i++) {
                            auto p_comm_unshifted = lagrange_msm_component::generate_assignments(assignment, {params.input.PI.neg_pub, params.input.PI.lagrange_bases}, row);
                            row = row + lagrange_msm_component::rows_amount;
                            //params.input.proofs[i].transcript.absorb_assignment(assignment, neg_res[0], row);
                            //params.input.proofs[i].transcript.absorb_assignment(assignment, neg_res[1], row);
                            /* for(std::size_t j = 0-; j < params.input.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.witness_comm[j].unshifted[k].size(); k++) {
                                    params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.witness_comm[j].unshifted[k], row);
                                }
                            } 
                            */
                            //joint_combiner = transcript.squeeze().to_field() add to public input
                            //for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_runtime_comm[j].unshifted[k].size(); k++) {
                            // params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k], row);
                            //}
                            /* for(std::size_t j = 0-; j < n_wires; j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_sorted_comm.unshifted[k].size(); k++) {
                                    params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].lookup_sorted_comm[j].unshifted[k], row);
                                }
                            } 
                            */
                           //  auto beta, gamma = transcript.squeeze()
                           /*
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_agg_comm.unshifted[k].size(); k++) {
                                    params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].lookup_agg_comm[j].unshifted[k], row);

                            } 
                            */
                            //for(std::size_t k = 0; k < params.input.proofs[i].comm.z_comm.unshifted[k].size(); k++) {
                            // params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.z_comm.unshifted[k], row);
                            //}
                            // auto alfa = transcript.squeeze(). to_field();

                            //for(std::size_t k = 0; k < permuts; k++) {
                            // params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.t_comm.unshifted[k], row);
                            //}

                            // auto zeta = transcript.squeeze(). to_field();
                            //get digest from transcript
                            std::vector<var_ec_point> shifted_commitments;
                            std::size_t max_size = 0;
                            std::vector<std::vector<var_ec_point>> unshifted_commitments(size);

                            for(std::size_t j = 0; j < params.input.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.witness_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[0].push_back(params.input.proofs[i].comm.witness_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.witness_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.witness_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.witness_comm[j].shifted);
                            } 
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.coefficient_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.coefficient_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[1].push_back(params.input.proofs[i].comm.coefficient_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.coefficient_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.coefficient_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.coefficient_comm[j].shifted);
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.z_comm.unshifted.size(); k++) {
                                    unshifted_commitments[2].push_back(params.input.proofs[i].comm.z_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.z_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.z_comm.unshifted.size();
                                }
                            shifted_commitments.push_back(params.input.proofs[i].comm.z_comm.shifted);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_sorted_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[3].push_back(params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.lookup_sorted_comm[j].shifted);
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_agg_comm.unshifted.size(); k++) {
                                    unshifted_commitments[4].push_back(params.input.proofs[i].comm.lookup_agg_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.lookup_agg_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_agg_comm.unshifted.size();
                                }
                            shifted_commitments.push_back(params.input.proofs[i].comm.lookup_agg_comm.shifted);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_selectors_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[5].push_back(params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.lookup_selectors_comm[j].shifted);
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size(); k++) {
                                    unshifted_commitments[6].push_back(params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size();
                                }
                            shifted_commitments.push_back(params.input.proofs[i].comm.lookup_runtime_comm.shifted);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.selectors_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.selectors_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[7].push_back(params.input.proofs[i].comm.selectors_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.selectors_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.selectors_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.selectors_comm[j].shifted);
                            }
                            //to-do: U = zero()
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type U = algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();
                            assignment.witness(W0)[row] = U.X;
                            assignment.witness(W1)[row] = U.Y;
                            std::size_t urow = row;
                            auto shifted_commitment_type_shifted = msm_component::generate_assignments(assignment, {params.input.proofs[i].scalars, shifted_commitments}, row);
                            row+= msm_component::rows_amount;
                            std::vector<var_ec_point> shifted_commitment_type_unshifted; 
                            for(std::size_t j = 0; j < max_size; j ++) {
                                std::vector<var_ec_point> part_unshifted_commitments;
                                std::vector<var> part_scalars;
                                for (std::size_t k = 0; k < size; k++) {
                                    if (k < unshifted_commitments[j].size()){ 
                                        part_unshifted_commitments.push_back(unshifted_commitments[j][k]);
                                        part_scalars.push_back(params.input.proofs[i].scalars[k]);
                                    } else {
                                        part_unshifted_commitments.push_back({var(W0, urow, false), var(W1, urow, false)});
                                        part_scalars.push_back(params.input.proofs[i].scalars[k]);
                                    }
                                }
                                auto res = msm_component::generate_assignments(assignment, {part_scalars, part_unshifted_commitments}, row);
                                shifted_commitment_type_unshifted.push_back({res.sum.X, res.sum.Y});
                                row+= msm_component::rows_amount;
                            }
                            auto chunked_shifted_commitment_type_shifted = shifted_commitment_type_shifted.sum;
                            var_ec_point chunked_shifted_commitment_type_unshifted = {var(0, urow, false), var(1, urow, false)};
                            row++;

                            for(std::size_t j = 0; j < shifted_commitment_type_unshifted.size(); j ++) {
                                auto res0 = scalar_mul_component::generate_assignments(assignment, {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, params.input.PI.zeta_to_srs_len}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res0.X, res0.Y};
                                auto res1 = add_component::generate_assignments(assignment, {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, {shifted_commitment_type_unshifted[j].X, shifted_commitment_type_unshifted[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res1.X, res1.Y};

                            }
                            auto chunked_t_comm_shifted = scalar_mul_component::generate_assignments(assignment, 
                            {{ params.input.proofs[i].comm.t_comm.shifted.X,  params.input.proofs[i].comm.t_comm.shifted.Y}, params.input.PI.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            var_ec_point chunked_t_comm_unshifted = {var(0, urow, false), var(1, urow, false)};;
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.t_comm.unshifted.size(); j++) {
                                auto res0 = scalar_mul_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y}, params.input.PI.zeta_to_srs_len}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_t_comm_unshifted = {res0.X, res0.Y};
                                auto res1 = add_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {params.input.proofs[i].comm.t_comm.unshifted[j].X, params.input.proofs[i].comm.t_comm.unshifted[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_t_comm_unshifted = {res1.X, res1.Y};
                            }
                            auto chunk_res_unshifted = scalar_mul_component::generate_assignments(assignment, 
                            {{ chunked_t_comm_unshifted.X,  chunked_t_comm_unshifted.Y}, params.input.PI.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            typename BlueprintFieldType::value_type minus_1 = -1;
                            auto const_res_unshifted = const_mul_component::generate_assignments(assignment, 
                            {chunk_res_unshifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            chunked_t_comm_unshifted = {chunk_res_unshifted.X, const_res_unshifted.output};

                            auto const_res_shifted = const_mul_component::generate_assignments(assignment, 
                            {chunked_t_comm_shifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            var_ec_point chunked_t_comm_shifted_res = {chunked_t_comm_shifted.X, const_res_unshifted.output};

                            auto ft_comm_unshifted = add_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}}, row);
                            row+=add_component::rows_amount;
                            auto ft_comm_shifted = add_component::generate_assignments(assignment, {{chunked_t_comm_shifted_res.X, chunked_t_comm_shifted_res.Y},
                                 {chunked_shifted_commitment_type_shifted.X, chunked_shifted_commitment_type_shifted.Y}}, row);
                            row+=add_component::rows_amount;
                            shifted_commitment_type ft_comm = {{ft_comm_shifted.X, ft_comm_shifted.Y}, {{ft_comm_unshifted.X, ft_comm_unshifted.Y}}};

                            std::vector<shifted_commitment_type> evaluations;
                            //shifted_commitment_type p_comm = {none, p_comm_unshifted};
                            shifted_commitment_type p_comm = {{p_comm_unshifted.sum.X, p_comm_unshifted.sum.Y}, {{p_comm_unshifted.sum.X, p_comm_unshifted.sum.Y}}};
                            evaluations.push_back(p_comm);
                            evaluations.push_back(ft_comm);
                            evaluations.push_back(params.input.proofs[i].comm.z_comm);
                            evaluations.push_back(params.input.proofs[i].comm.generic_comm);
                            evaluations.push_back(params.input.proofs[i].comm.psm_comm);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.oracles_poly_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.oracles_poly_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.witness_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.witness_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.sigma_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.sigma_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_sorted_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.lookup_sorted_comm[j]);
                            }
                            evaluations.push_back(params.input.proofs[i].comm.lookup_agg_comm);
                            evaluations.push_back(params.input.proofs[i].comm.table_comm);
                            evaluations.push_back(params.input.proofs[i].comm.lookup_runtime_comm);
                            typename batch_verify_component::params_type::var_proof p = {/*params.input.proofs[i].transcript,*/ {evaluations},
                             params.input.proofs[i].o};
                            batch_proofs.push_back(p);
                        }
                        typename batch_verify_component::params_type::public_input pi = {params.input.PI.cip};
                        typename batch_verify_component::params_type batch_params = {{batch_proofs, params.input.verifier_index,  pi}, params.fr_data};
                        batch_verify_component::generate_assignments(assignment, batch_params, row);
                        row+=batch_verify_component::rows_amount;

                        
                        typename proof_binding::fq_data<var> fq_data_recalculated;
                        map_fq_component::generate_assignments(assignment,
                            {params.fq_data, fq_data_recalculated}, row);
                        row += map_fq_component::rows_amount;
                        return result_type(component_start_row);
                    }

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t row = start_row_index;
                        std::size_t p_size = params.input.proofs.size();
                        std::vector<typename batch_verify_component::params_type::var_proof> batch_proofs;
                        for(std::size_t i = 0; i < p_size; i++) {
                            auto p_comm_unshifted = lagrange_msm_component::generate_circuit(bp, assignment, {params.input.PI.neg_pub, params.input.PI.lagrange_bases}, row);
                            row = row + lagrange_msm_component::rows_amount;
                            //params.input.proofs[i].transcript.absorb_assignment(assignment, neg_res[0], row);
                            //params.input.proofs[i].transcript.absorb_assignment(assignment, neg_res[1], row);
                            /* for(std::size_t j = 0-; j < params.input.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.witness_comm[j].unshifted[k].size(); k++) {
                                    params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.witness_comm[j].unshifted[k], row);
                                }
                            } 
                            */
                            //joint_combiner = transcript.squeeze().to_field() add to public input
                            //for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_runtime_comm[j].unshifted[k].size(); k++) {
                            // params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k], row);
                            //}
                            /* for(std::size_t j = 0-; j < n_wires; j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_sorted_comm.unshifted[k].size(); k++) {
                                    params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].lookup_sorted_comm[j].unshifted[k], row);
                                }
                            } 
                            */
                           //  auto beta, gamma = transcript.squeeze()
                           /*
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_agg_comm.unshifted[k].size(); k++) {
                                    params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].lookup_agg_comm[j].unshifted[k], row);

                            } 
                            */
                            //for(std::size_t k = 0; k < params.input.proofs[i].comm.z_comm.unshifted[k].size(); k++) {
                            // params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.z_comm.unshifted[k], row);
                            //}
                            // auto alfa = transcript.squeeze(). to_field();

                            //for(std::size_t k = 0; k < permuts; k++) {
                            // params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].comm.t_comm.unshifted[k], row);
                            //}

                            // auto zeta = transcript.squeeze(). to_field();
                            //get digest from transcript
                            std::vector<var_ec_point> shifted_commitments;
                            std::size_t max_size = 0;
                            std::vector<std::vector<var_ec_point>> unshifted_commitments(size);

                            for(std::size_t j = 0; j < params.input.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.witness_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[0].push_back(params.input.proofs[i].comm.witness_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.witness_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.witness_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.witness_comm[j].shifted);
                            } 
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.coefficient_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.coefficient_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[1].push_back(params.input.proofs[i].comm.coefficient_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.coefficient_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.coefficient_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.coefficient_comm[j].shifted);
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.z_comm.unshifted.size(); k++) {
                                    unshifted_commitments[2].push_back(params.input.proofs[i].comm.z_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.z_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.z_comm.unshifted.size();
                                }
                            shifted_commitments.push_back(params.input.proofs[i].comm.z_comm.shifted);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_sorted_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[3].push_back(params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.lookup_sorted_comm[j].shifted);
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_agg_comm.unshifted.size(); k++) {
                                    unshifted_commitments[4].push_back(params.input.proofs[i].comm.lookup_agg_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.lookup_agg_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_agg_comm.unshifted.size();
                                }
                            shifted_commitments.push_back(params.input.proofs[i].comm.lookup_agg_comm.shifted);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_selectors_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[5].push_back(params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.lookup_selectors_comm[j].shifted);
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size(); k++) {
                                    unshifted_commitments[6].push_back(params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size();
                                }
                            shifted_commitments.push_back(params.input.proofs[i].comm.lookup_runtime_comm.shifted);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.selectors_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.selectors_comm[j].unshifted.size(); k++) {
                                    unshifted_commitments[7].push_back(params.input.proofs[i].comm.selectors_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.selectors_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.selectors_comm[j].unshifted.size();
                                }
                                shifted_commitments.push_back(params.input.proofs[i].comm.selectors_comm[j].shifted);
                            }
                            //to-do: U = zero()
                            std::size_t urow = row;
                            auto shifted_commitment_type_shifted = msm_component::generate_circuit(bp, assignment, {params.input.proofs[i].scalars, shifted_commitments}, row);
                            row+= msm_component::rows_amount;
                            std::vector<var_ec_point> shifted_commitment_type_unshifted; 
                            for(std::size_t j = 0; j < max_size; j ++) {
                                std::vector<var_ec_point> part_unshifted_commitments;
                                std::vector<var> part_scalars;
                                for (std::size_t k = 0; k < size; k++) {
                                    if (k < unshifted_commitments[j].size()){
                                        part_unshifted_commitments.push_back(unshifted_commitments[j][k]);
                                        part_scalars.push_back(params.input.proofs[i].scalars[k]);
                                    } else {
                                        part_unshifted_commitments.push_back({var(W0, urow, false), var(W1, urow, false)});
                                        part_scalars.push_back(params.input.proofs[i].scalars[k]);
                                    }
                                }
                                auto res = msm_component::generate_circuit(bp, assignment, {part_scalars, part_unshifted_commitments}, row);
                                shifted_commitment_type_unshifted.push_back({res.sum.X, res.sum.Y});
                                row+= msm_component::rows_amount;
                            }
                            auto chunked_shifted_commitment_type_shifted = shifted_commitment_type_shifted.sum;
                            var_ec_point chunked_shifted_commitment_type_unshifted = {var(0, urow, false), var(1, urow, false)};
                            row++;

                            for(std::size_t j = 0; j < shifted_commitment_type_unshifted.size(); j ++) {
                                auto res0 = scalar_mul_component::generate_circuit(bp, assignment, {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, params.input.PI.zeta_to_srs_len}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res0.X, res0.Y};
                                zk::components::generate_circuit<add_component>(bp, assignment, 
                                {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, {shifted_commitment_type_unshifted[j].X, shifted_commitment_type_unshifted[j].Y}}, row);
                                typename add_component::result_type res1({{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, {shifted_commitment_type_unshifted[j].X, shifted_commitment_type_unshifted[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res1.X, res1.Y};

                            }
                            auto chunked_t_comm_shifted = scalar_mul_component::generate_circuit(bp, assignment, 
                            {{ params.input.proofs[i].comm.t_comm.shifted.X,  params.input.proofs[i].comm.t_comm.shifted.Y}, params.input.PI.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            var_ec_point chunked_t_comm_unshifted = {var(0, urow, false), var(1, urow, false)};;
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.t_comm.unshifted.size(); j++) {
                                auto res0 = scalar_mul_component::generate_circuit(bp, assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y}, params.input.PI.zeta_to_srs_len}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_t_comm_unshifted = {res0.X, res0.Y};
                                zk::components::generate_circuit<add_component>(bp, assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {params.input.proofs[i].comm.t_comm.unshifted[j].X, params.input.proofs[i].comm.t_comm.unshifted[j].Y}}, row);
                                typename add_component::result_type res1({{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {params.input.proofs[i].comm.t_comm.unshifted[j].X, params.input.proofs[i].comm.t_comm.unshifted[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_t_comm_unshifted = {res1.X, res1.Y};
                            }
                            auto chunk_res_unshifted = scalar_mul_component::generate_circuit(bp, assignment, 
                            {{ chunked_t_comm_unshifted.X,  chunked_t_comm_unshifted.Y}, params.input.PI.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            typename BlueprintFieldType::value_type minus_1 = -1;
                            zk::components::generate_circuit<const_mul_component>(bp, assignment, 
                            {chunk_res_unshifted.Y, minus_1}, row);
                            typename const_mul_component::result_type const_res_unshifted({chunk_res_unshifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            chunked_t_comm_unshifted = {chunk_res_unshifted.X, const_res_unshifted.output};
;
                            zk::components::generate_circuit<const_mul_component>(bp, assignment, 
                            {chunked_t_comm_shifted.Y, minus_1}, row);
                            typename const_mul_component::result_type const_res_shifted({chunked_t_comm_shifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            var_ec_point chunked_t_comm_shifted_res = {chunked_t_comm_shifted.X, const_res_unshifted.output};

                            zk::components::generate_circuit<add_component>(bp, assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}}, row);
                                typename add_component::result_type ft_comm_unshifted({{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}}, row);
                            row+=add_component::rows_amount;
                            zk::components::generate_circuit<add_component>(bp, assignment, {{chunked_t_comm_shifted_res.X, chunked_t_comm_shifted_res.Y},
                                 {chunked_shifted_commitment_type_shifted.X, chunked_shifted_commitment_type_shifted.Y}}, row);
                                typename add_component::result_type ft_comm_shifted({{chunked_t_comm_shifted_res.X, chunked_t_comm_shifted_res.Y},
                                 {chunked_shifted_commitment_type_shifted.X, chunked_shifted_commitment_type_shifted.Y}}, row);
                            row+=add_component::rows_amount;
                            shifted_commitment_type ft_comm = {{ft_comm_shifted.X, ft_comm_shifted.Y}, {{ft_comm_unshifted.X, ft_comm_unshifted.Y}}};

                            std::vector<shifted_commitment_type> evaluations;
                            //shifted_commitment_type p_comm = {none, p_comm_unshifted};
                            shifted_commitment_type p_comm = {{p_comm_unshifted.sum.X, p_comm_unshifted.sum.Y}, {{p_comm_unshifted.sum.X, p_comm_unshifted.sum.Y}}};
                            evaluations.push_back(p_comm);
                            evaluations.push_back(ft_comm);
                            evaluations.push_back(params.input.proofs[i].comm.z_comm);
                            evaluations.push_back(params.input.proofs[i].comm.generic_comm);
                            evaluations.push_back(params.input.proofs[i].comm.psm_comm);
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.oracles_poly_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.oracles_poly_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.witness_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.witness_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.sigma_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.sigma_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_sorted_comm.size(); j++){
                                evaluations.push_back(params.input.proofs[i].comm.lookup_sorted_comm[j]);
                            }
                            evaluations.push_back(params.input.proofs[i].comm.lookup_agg_comm);
                            evaluations.push_back(params.input.proofs[i].comm.table_comm);
                            evaluations.push_back(params.input.proofs[i].comm.lookup_runtime_comm);
                            typename batch_verify_component::params_type::var_proof p = {/*params.input.proofs[i].transcript,*/ {evaluations},
                             params.input.proofs[i].o};
                            batch_proofs.push_back(p);
                        }
                        typename batch_verify_component::params_type::public_input pi = {params.input.PI.cip};
                        typename batch_verify_component::params_type batch_params = {{batch_proofs, params.input.verifier_index,  pi}, params.fr_data};
                        batch_verify_component::generate_circuit(bp, assignment, batch_params, row);
                        row+=batch_verify_component::rows_amount;

                        typename proof_binding::fq_data<var> fq_data_recalculated;
                        map_fq_component::generate_circuit(bp, assignment,
                            {params.fq_data, fq_data_recalculated}, row);
                        row += map_fq_component::rows_amount;
                        
                        return result_type(start_row_index);
                    }

                private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        const std::size_t first_selector_index) {
                        
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP

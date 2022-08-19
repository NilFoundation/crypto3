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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/commitment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/map_fq.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>

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
                         std::size_t... WireIndexes>
                class base_field;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType,
                         std::size_t BatchSize,
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

                    using proof_type = kimchi_proof_base<BlueprintFieldType, KimchiParamsType>;
                    constexpr static const std::size_t f_comm_base_size = proof_type::f_comm_base_size;

                    using msm_component = zk::components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType, 
                        f_comm_base_size,
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using lagrange_msm_component = zk::components::element_g1_multi_scalar_mul< ArithmetizationType, CurveType, 
                        KimchiParamsType::public_input_size,
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> ;

                    using scalar_mul_component =
                        zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    using add_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                                       W4, W5, W6, W7, W8, W9, W10>;

                    using proof_binding = typename zk::components::binding<ArithmetizationType,
                        BlueprintFieldType, KimchiParamsType>;

                    using map_fq_component = zk::components::map_fq<ArithmetizationType, 
                        CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize,
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using batch_proof_type = typename 
                        zk::components::batch_evaluation_proof_base<BlueprintFieldType, 
                            ArithmetizationType, KimchiParamsType,
                            KimchiCommitmentParamsType>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType,
                        KimchiParamsType>;

                    using commitment_type = typename 
                        zk::components::kimchi_commitment_type<BlueprintFieldType, 
                            KimchiCommitmentParamsType::shifted_commitment_split>;

                    using w_comm_type = typename 
                        zk::components::kimchi_commitment_type<BlueprintFieldType, 
                            KimchiCommitmentParamsType::w_comm_size>;

                    using batch_verify_component =
                        zk::components::batch_verify_base_field<ArithmetizationType, CurveType, 
                                            KimchiParamsType, KimchiCommitmentParamsType, BatchSize, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    
                    using kimchi_constants = zk::components::kimchi_inner_constants<KimchiParamsType>;

                    constexpr static const std::size_t selector_seed = 0xff91;

                public:
                    constexpr static const std::size_t rows_amount = (1 + (2 + 2*KimchiCommitmentParamsType::shifted_commitment_split) * (scalar_mul_component::rows_amount + add_component::rows_amount) 
                        + (KimchiCommitmentParamsType::shifted_commitment_split + 1) * msm_component::rows_amount + 
                        lagrange_msm_component::rows_amount + 2 * const_mul_component::rows_amount 
                        ) * BatchSize
                        + batch_verify_component::rows_amount
                        + map_fq_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<proof_type, BatchSize> proofs;
                        verifier_index_type verifier_index;
                        
                        typename proof_binding::template fr_data<var, BatchSize> fr_data;
                        typename proof_binding::template fq_data<var> fq_data;
                    };

                    struct result_type {

                        result_type(std::size_t component_start_row) {
                        }
                    };

                    private:

                    template<std::size_t CommSize>
                    static void parse_commitments(
                        std::array<std::vector<var_ec_point>, 
                            f_comm_base_size> &unshifted_commitments,
                        const std::array<commitment_type, CommSize> comms,
                        std::size_t &comm_idx) {
                        
                        for(std::size_t j = 0; j < CommSize; j ++) {
                            for(std::size_t k = 0; k < comms[j].parts.size(); k++) {
                                unshifted_commitments[comm_idx].push_back(comms[j].parts[k]);
                            }
                            comm_idx++;
                        } 
                    }

                    static std::array<std::vector<var_ec_point>, 
                        f_comm_base_size> prepare_f_comm(const params_type &params) {

                        std::array<std::vector<var_ec_point>, 
                            f_comm_base_size> unshifted_commitments;
                        std::size_t comm_idx = 0;

                        parse_commitments<1>(unshifted_commitments, 
                            {params.verifier_index.comm.sigma_comm[KimchiParamsType::permut_size - 1]}, 
                            comm_idx);

                        // take generic_size coeff_comm
                        std::array<commitment_type, kimchi_constants::ft_generic_size> generic_comm;
                        for (std::size_t i = 0; i < generic_comm.size(); i++) {
                            generic_comm[i] = params.verifier_index.comm.coefficient_comm[i];
                        }

                        parse_commitments<kimchi_constants::ft_generic_size>(
                            unshifted_commitments,
                            generic_comm,
                            comm_idx
                        );

                        // for term in terms:
                        // fill_shifted_commitments(params.proofs[i].comm.witness_comm,
                        //     params.proofs[i].comm.witness_comm.size());

                        // fill_shifted_commitments(params.verifier_index.comm.coefficient_comm,
                        //     params.verifier_index.comm.coefficient_comm.size());

                        // fill_shifted_commitments({params.proofs[i].comm.z_comm},
                        //     1);

                        // fill_shifted_commitments(params.proofs[i].comm.lookup_sorted_comm,
                        //     params.proofs[i].comm.lookup_sorted_comm.size());

                        // fill_shifted_commitments({params.proofs[i].comm.lookup_agg_comm},
                        //     1);

                        // fill_shifted_commitments(params.verifier_index.comm.lookup_selectors_comm,
                        //     params.verifier_index.comm.lookup_selectors_comm.size());

                        // fill_shifted_commitments({params.proofs[i].comm.lookup_runtime_comm},
                        //     1);

                        // fill_shifted_commitments(params.verifier_index.comm.selectors_comm,
                        //     params.verifier_index.comm.selectors_comm.size());

                        return unshifted_commitments;
                    }

                    public:

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        std::array<batch_proof_type, BatchSize> batch_proofs;

                        for(std::size_t i = 0; i < BatchSize; i++) {

                            auto p_comm_unshifted = lagrange_msm_component::generate_assignments(assignment, 
                                {params.fr_data.neg_pub, params.verifier_index.lagrange_bases}, row);
                            row = row + lagrange_msm_component::rows_amount;

                            //Oracles
                            //params.proofs[i].transcript.absorb_assignment(assignment, neg_res[0], row);
                            //params.proofs[i].transcript.absorb_assignment(assignment, neg_res[1], row);
                            /* for(std::size_t j = 0-; j < params.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.proofs[i].comm.witness_comm[j].parts[k].size(); k++) {
                                    params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.witness_comm[j].parts[k], row);
                                }
                            } 
                            */
                            //joint_combiner = transcript.squeeze().to_field() add to public input
                            //for(std::size_t k = 0; k < params.proofs[i].comm.lookup_runtime_comm[j].parts[k].size(); k++) {
                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.lookup_runtime_comm.parts[k], row);
                            //}
                            /* for(std::size_t j = 0-; j < n_wires; j ++) {
                                for(std::size_t k = 0; k < params.proofs[i].comm.lookup_sorted_comm.parts[k].size(); k++) {
                                    params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].lookup_sorted_comm[j].parts[k], row);
                                }
                            } 
                            */
                           //  auto beta, gamma = transcript.squeeze()
                           /*
                                for(std::size_t k = 0; k < params.proofs[i].comm.lookup_agg_comm.parts[k].size(); k++) {
                                    params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].lookup_agg_comm[j].parts[k], row);

                            } 
                            */
                            //for(std::size_t k = 0; k < params.proofs[i].comm.z_comm.parts[k].size(); k++) {
                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.z_comm.parts[k], row);
                            //}
                            // auto alfa = transcript.squeeze(). to_field();

                            //for(std::size_t k = 0; k < permuts; k++) {
                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.t_comm.parts[k], row);
                            //}

                            // auto zeta = transcript.squeeze(). to_field();
                            //get digest from transcript


                            // f_comm
                            std::array<std::vector<var_ec_point>, f_comm_base_size>
                                unshifted_commitments = prepare_f_comm(params);

                            //to-do: U = zero()
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type U = 
                                algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();
                            assignment.witness(W0)[row] = U.X;
                            assignment.witness(W1)[row] = U.Y;
                            std::size_t urow = row;
                            std::array<var_ec_point, 
                                KimchiCommitmentParamsType::max_comm_size> shifted_commitment_type_unshifted; 
                            for(std::size_t j = 0; j < KimchiCommitmentParamsType::max_comm_size; j ++) {
                                std::array<var_ec_point, f_comm_base_size> part_unshifted_commitments;
                                std::array<var, f_comm_base_size> part_scalars;
                                for (std::size_t k = 0; k < f_comm_base_size; k++) {
                                    if (j < unshifted_commitments[k].size()) {
                                        part_unshifted_commitments[k] = unshifted_commitments[k][j];
                                        part_scalars[k] = params.proofs[i].scalars[k];
                                    }
                                }
                                auto res = msm_component::generate_assignments(assignment, {part_scalars, part_unshifted_commitments}, row);
                                shifted_commitment_type_unshifted[j] = {res.sum.X, res.sum.Y};
                                row+= msm_component::rows_amount;
                            }
                            var_ec_point chunked_shifted_commitment_type_unshifted = {var(0, urow, false), var(1, urow, false)};
                            row++;

                            for(std::size_t j = 0; j < shifted_commitment_type_unshifted.size(); j ++) {
                                auto res0 = scalar_mul_component::generate_assignments(assignment, 
                                    {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, 
                                    params.fr_data.zeta_to_srs_len[i]}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res0.X, res0.Y};
                                auto res1 = add_component::generate_assignments(assignment,
                                    {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y},
                                    {shifted_commitment_type_unshifted[j].X, shifted_commitment_type_unshifted[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res1.X, res1.Y};

                            }

                            var_ec_point chunked_t_comm_unshifted = {var(0, urow, false), var(1, urow, false)};;
                            for(std::size_t j = 0; j < params.proofs[i].comm.t_comm.parts.size(); j++) {
                                auto res0 = scalar_mul_component::generate_assignments(assignment, 
                                    {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y}, 
                                    params.fr_data.zeta_to_srs_len[i]}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_t_comm_unshifted = {res0.X, res0.Y};
                                auto res1 = add_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {params.proofs[i].comm.t_comm.parts[j].X, params.proofs[i].comm.t_comm.parts[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_t_comm_unshifted = {res1.X, res1.Y};
                            }
                            auto chunk_res_unshifted = scalar_mul_component::generate_assignments(assignment, 
                            {{ chunked_t_comm_unshifted.X,  chunked_t_comm_unshifted.Y}, params.fr_data.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            typename BlueprintFieldType::value_type minus_1 = -1;
                            auto const_res_unshifted = const_mul_component::generate_assignments(assignment, 
                            {chunk_res_unshifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            chunked_t_comm_unshifted = {chunk_res_unshifted.X, const_res_unshifted.output};

                            auto ft_comm_unshifted = add_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}}, row);
                            row+=add_component::rows_amount;
                            commitment_type ft_comm = {{{ft_comm_unshifted.X, ft_comm_unshifted.Y}}};

                            std::array<commitment_type,
                                kimchi_constants::evaluations_in_batch_size> evaluations;
                            std::size_t eval_idx = 0;

                            for (auto chal : params.proofs[i].comm.prev_challenges) {
                                evaluations[eval_idx++] = chal;
                            }

                            //commitment_type p_comm = {none, p_comm_unshifted};
                            commitment_type p_comm = {{{p_comm_unshifted.sum.X, p_comm_unshifted.sum.Y}}};
                            evaluations[eval_idx++] = p_comm;
                            evaluations[eval_idx++] = ft_comm;
                            evaluations[eval_idx++] = params.proofs[i].comm.z_comm;
                            evaluations[eval_idx++] = params.verifier_index.comm.generic_comm;
                            evaluations[eval_idx++] = params.verifier_index.comm.psm_comm;

                            for(std::size_t j = 0; j < params.proofs[i].comm.witness_comm.size(); j++){
                                evaluations[eval_idx++] = params.proofs[i].comm.witness_comm[j];
                            }
                            for(std::size_t j = 0; j < params.verifier_index.comm.sigma_comm.size() - 1; j++){
                                evaluations[eval_idx++] = params.verifier_index.comm.sigma_comm[j];
                            }

                            //to-do lookups
                            // for(std::size_t j = 0; j < params.proofs[i].comm.lookup_sorted_comm.size(); j++){
                            //     evaluations[eval_idx++] = params.proofs[i].comm.lookup_sorted_comm[j];
                            // }
                            // evaluations[eval_idx++] = params.proofs[i].comm.lookup_agg_comm;
                            // evaluations[eval_idx++] = params.proofs[i].comm.table_comm;
                            // evaluations[eval_idx++] = params.proofs[i].comm.lookup_runtime_comm;

                            assert(eval_idx == kimchi_constants::evaluations_in_batch_size);

                            batch_proof_type p = {/*params.proofs[i].transcript,*/ {evaluations},
                                params.proofs[i].o};
                        
                            batch_proofs[i] = p;
                        }
                        typename batch_verify_component::params_type batch_params = {batch_proofs, params.verifier_index, params.fr_data};
                        batch_verify_component::generate_assignments(assignment, batch_params, row);
                        row+=batch_verify_component::rows_amount;

                        
                        typename proof_binding::template fq_data<var> fq_data_recalculated;
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
                        std::array<batch_proof_type, BatchSize> batch_proofs;
                        for(std::size_t i = 0; i < BatchSize; i++) {
                            auto p_comm_unshifted = lagrange_msm_component::generate_circuit(bp, assignment,
                                 {params.fr_data.neg_pub, params.verifier_index.lagrange_bases}, row);
                            row = row + lagrange_msm_component::rows_amount;
                            //params.proofs[i].transcript.absorb_assignment(assignment, neg_res[0], row);
                            //params.proofs[i].transcript.absorb_assignment(assignment, neg_res[1], row);
                            /* for(std::size_t j = 0-; j < params.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.proofs[i].comm.witness_comm[j].parts[k].size(); k++) {
                                    params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.witness_comm[j].parts[k], row);
                                }
                            } 
                            */
                            //joint_combiner = transcript.squeeze().to_field() add to public input
                            //for(std::size_t k = 0; k < params.proofs[i].comm.lookup_runtime_comm[j].parts[k].size(); k++) {
                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.lookup_runtime_comm.parts[k], row);
                            //}
                            /* for(std::size_t j = 0-; j < n_wires; j ++) {
                                for(std::size_t k = 0; k < params.proofs[i].comm.lookup_sorted_comm.parts[k].size(); k++) {
                                    params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].lookup_sorted_comm[j].parts[k], row);
                                }
                            } 
                            */
                           //  auto beta, gamma = transcript.squeeze()
                           /*
                                for(std::size_t k = 0; k < params.proofs[i].comm.lookup_agg_comm.parts[k].size(); k++) {
                                    params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].lookup_agg_comm[j].parts[k], row);

                            } 
                            */
                            //for(std::size_t k = 0; k < params.proofs[i].comm.z_comm.parts[k].size(); k++) {
                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.z_comm.parts[k], row);
                            //}
                            // auto alfa = transcript.squeeze(). to_field();

                            //for(std::size_t k = 0; k < permuts; k++) {
                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].comm.t_comm.parts[k], row);
                            //}

                            // auto zeta = transcript.squeeze(). to_field();
                            //get digest from transcript
                            
                            std::array<std::vector<var_ec_point>, f_comm_base_size>
                                unshifted_commitments = prepare_f_comm(params);
                                
                            //to-do: U = zero()
                            std::size_t urow = row;
                            std::array<var_ec_point,
                                KimchiCommitmentParamsType::max_comm_size> shifted_commitment_type_unshifted; 
                            for(std::size_t j = 0; j < KimchiCommitmentParamsType::max_comm_size; j ++) {
                                std::array<var_ec_point, f_comm_base_size> part_unshifted_commitments;
                                std::array<var, f_comm_base_size> part_scalars;
                                for (std::size_t k = 0; k < f_comm_base_size; k++) {
                                    if (j < unshifted_commitments[k].size()) {
                                        part_unshifted_commitments[k] = unshifted_commitments[k][j];
                                        part_scalars[k] = params.proofs[i].scalars[k];
                                    }
                                }
                                auto res = msm_component::generate_circuit(bp, assignment, {part_scalars, part_unshifted_commitments}, row);
                                shifted_commitment_type_unshifted[j] = {res.sum.X, res.sum.Y};
                                row += msm_component::rows_amount;
                            }
                            var_ec_point chunked_shifted_commitment_type_unshifted = {var(0, urow, false), var(1, urow, false)};
                            row++;

                            for(std::size_t j = 0; j < shifted_commitment_type_unshifted.size(); j ++) {
                                auto res0 = scalar_mul_component::generate_circuit(bp, assignment,
                                    {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y},
                                    params.fr_data.zeta_to_srs_len[i]}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res0.X, res0.Y};
                                zk::components::generate_circuit<add_component>(bp, assignment, 
                                {{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, {shifted_commitment_type_unshifted[j].X, shifted_commitment_type_unshifted[j].Y}}, row);
                                typename add_component::result_type res1({{chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}, {shifted_commitment_type_unshifted[j].X, shifted_commitment_type_unshifted[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_shifted_commitment_type_unshifted = {res1.X, res1.Y};

                            }

                            var_ec_point chunked_t_comm_unshifted = {var(0, urow, false), var(1, urow, false)};;
                            for(std::size_t j = 0; j < params.proofs[i].comm.t_comm.parts.size(); j++) {
                                auto res0 = scalar_mul_component::generate_circuit(bp, assignment,
                                    {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                    params.fr_data.zeta_to_srs_len[i]}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_t_comm_unshifted = {res0.X, res0.Y};
                                zk::components::generate_circuit<add_component>(bp, assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {params.proofs[i].comm.t_comm.parts[j].X, params.proofs[i].comm.t_comm.parts[j].Y}}, row);
                                typename add_component::result_type res1({{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {params.proofs[i].comm.t_comm.parts[j].X, params.proofs[i].comm.t_comm.parts[j].Y}}, row);
                                row+=add_component::rows_amount;
                                chunked_t_comm_unshifted = {res1.X, res1.Y};
                            }
                            auto chunk_res_unshifted = scalar_mul_component::generate_circuit(bp, assignment, 
                            {{ chunked_t_comm_unshifted.X,  chunked_t_comm_unshifted.Y}, params.fr_data.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            typename BlueprintFieldType::value_type minus_1 = -1;
                            zk::components::generate_circuit<const_mul_component>(bp, assignment, 
                            {chunk_res_unshifted.Y, minus_1}, row);
                            typename const_mul_component::result_type const_res_unshifted({chunk_res_unshifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            chunked_t_comm_unshifted = {chunk_res_unshifted.X, const_res_unshifted.output};

                            zk::components::generate_circuit<add_component>(bp, assignment, {{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}}, row);
                                typename add_component::result_type ft_comm_unshifted({{chunked_t_comm_unshifted.X, chunked_t_comm_unshifted.Y},
                                 {chunked_shifted_commitment_type_unshifted.X, chunked_shifted_commitment_type_unshifted.Y}}, row);
                            row+=add_component::rows_amount;
                            commitment_type ft_comm = {{{ft_comm_unshifted.X, ft_comm_unshifted.Y}}};

                            std::array<commitment_type,
                                kimchi_constants::evaluations_in_batch_size> evaluations;
                            std::size_t eval_idx = 0;
                            for (auto chal : params.proofs[i].comm.prev_challenges) {
                                evaluations[eval_idx++] = chal;
                            }
                            //commitment_type p_comm = {none, p_comm_unshifted};
                            commitment_type p_comm = {{{p_comm_unshifted.sum.X, p_comm_unshifted.sum.Y}}};
                            evaluations[eval_idx++] = p_comm;
                            evaluations[eval_idx++] = ft_comm;
                            evaluations[eval_idx++] = params.proofs[i].comm.z_comm;
                            evaluations[eval_idx++] = params.verifier_index.comm.generic_comm;
                            evaluations[eval_idx++] = params.verifier_index.comm.psm_comm;

                            for(std::size_t j = 0; j < params.proofs[i].comm.witness_comm.size(); j++){
                                evaluations[eval_idx++] = params.proofs[i].comm.witness_comm[j];
                            }
                            for(std::size_t j = 0; j < params.verifier_index.comm.sigma_comm.size() - 1; j++){
                                evaluations[eval_idx++] = params.verifier_index.comm.sigma_comm[j];
                            }

                            // for(std::size_t j = 0; j < params.proofs[i].comm.lookup_sorted_comm.size(); j++){
                            //     evaluations[eval_idx++] = params.proofs[i].comm.lookup_sorted_comm[j];
                            // }
                            // evaluations[eval_idx++] = params.proofs[i].comm.lookup_agg_comm;
                            // evaluations[eval_idx++] = params.proofs[i].comm.table_comm;
                            // evaluations[eval_idx++] = params.proofs[i].comm.lookup_runtime_comm;

                            assert(eval_idx == kimchi_constants::evaluations_in_batch_size);

                            batch_proof_type p = {/*params.proofs[i].transcript,*/ {evaluations},
                                params.proofs[i].o};
                            
                            batch_proofs[i] = p;
                        }
                        typename batch_verify_component::params_type batch_params = {batch_proofs, params.verifier_index, params.fr_data};
                        batch_verify_component::generate_circuit(bp, assignment, batch_params, row);
                        row+=batch_verify_component::rows_amount;

                        typename proof_binding::template fq_data<var> fq_data_recalculated;
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

#endif    // CRYPTO3_ZK_BLUEPRINT_BASE_FIELD_HPP

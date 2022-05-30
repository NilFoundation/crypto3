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
// @file Declaration of interfaces for auxiliary components for the BATCH_VERIFY_BASE_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_BASE_FIELD_HPP
#define CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_BASE_FIELD_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_base_field.hpp>
namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t batch_size, std::size_t lr_rounds,
                std::size_t n, std::size_t comm_size, std::size_t n_wires, std::size_t bases_size, std::size_t permuts,
                         std::size_t... WireIndexes>
                class batch_verify_base_field;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t n,
                         std::size_t bases_size,
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
                class batch_verify_base_field<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       CurveType,
                                                        n,
                                                        bases_size,
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
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using const_mul_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1, W2>;

                    using msm_component = zk::components::element_g1_multi_scalar_mul< ArithmetizationType, CurveType, bases_size,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> ;
                    using scalar_mul_component =
                        zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    using add_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                                       W4, W5, W6, W7, W8, W9, W10>;
                    using batch_verify_component =
                        zk::components::batch_verify_base_field<ArithmetizationType, CurveType, n, bases_size, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    using var_ec_point = typename msm_component::params_type::var_ec_point;

                    using f_comm = typename batch_verify_component::params_type::f_comm;

                    using opening_proof = typename batch_verify_component::params_type::opening_proof;

                    constexpr static const std::size_t selector_seed = 0xff91;

                public:
                    constexpr static const std::size_t rows_amount = 1 + sub_component::rows_amount + msm_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {

                        struct commitments {
                             std::vector<f_comm> witness_comm;
                             std::vector<f_comm> sigma_comm;
                             std::vector<f_comm> coefficient_comm;
                             std::vector<f_comm> oracles_poly_comm; // to-do: get in the component from oracles
                             f_comm lookup_runtime_comm;
                             f_comm table_comm;
                             std::vector<f_comm> lookup_sorted_comm;
                             std::vector<f_comm> lookup_selectors_comm;
                             std::vector<f_comm> selectors_comm;
                             f_comm lookup_agg_comm;
                             f_comm z_comm;
                             f_comm t_comm;
                             f_comm generic_comm;
                             f_comm psm_comm
                        }
                        struct var_proof {
                            kimchi_transcript<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                                          W11, W12, W13, W14> transcript;
                            commitments comm;
                            opening_proof o;
                            std::vector<var> scalars;
                        };
                        struct public_input {
                            std::array<var_ec_point, n> lagrange_bases;
                            std::vector<var> Pub;
                            var zeta_to_srs_len;
                            var zeta_to_domain_size_minus_1;
                            var_ec_point H;
                            std::array<var_ec_point, n> G;
                            std::vector<var> batch_scalars;
                            std::vector<var> cip;
                        };
                        struct result {
                            std::vector<var_proof> proofs;
                            public_input PI;
                        };
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
                            auto p_comm = msm_component::generate_assignments(assignment, {params.input.PI.pub, params.input.PI.lagrange_bases}, row);
                            row+= typename msm_component::rows_amount;
                            assignment.witness(W0)[row] = assignment.var_value(res.sum.X);
                            assignment.witness(W1)[row] = - assignment.var_value(res.sum.Y);;
                            neg_res = {var(W0, row, false), var(W1, row, false)}
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
                            std::size_t size = params.input.proofs[i].comm.witness_comm.size() + params.input.proofs[i].comm.coefficient_comm.size() +
                            1 + params.input.proofs[i].comm.lookup_sorted_comm.size() + 1 + params.input.proofs[i].comm.lookup_selectors_comm.size() +
                            1 +  params.input.proofs[i].comm.selectors_comm.size();
                            std::size_t max_size = 0;
                            std::vector<std::vector<var_ec_point>> unshifted_commitments(size);

                            for(std::size_t j = 0; j < params.input.proofs[i].comm.witness_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.witness_comm[j].unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.witness_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.witness_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.witness_comm[j].unshifted[k].size();
                                }
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.witness_comm[j].shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.witness_comm[j].shifted[k]);
                                }
                            } 
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.coefficient_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.coefficient_comm[j].unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.coefficient_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.coefficient_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.coefficient_comm[j].unshifted[k].size();
                                }
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.coefficient_comm[j].shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.coefficient_comm[j].shifted[k]);
                                }
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.z_comm.unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.z_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.z_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.z_comm.unshifted.size();
                                }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.z_comm.shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.z_comm.shifted[k]);
                                }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_sorted_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_sorted_comm[j].unshifted[k].size();
                                }
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_sorted_comm[j].shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.lookup_sorted_comm[j].shifted[k]);
                                }
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_agg_comm.unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.lookup_agg_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.lookup_agg_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_agg_comm.unshifted[k].size();
                                }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_agg_comm.shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.lookup_agg_comm.shifted[k]);
                                }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.lookup_selectors_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_selectors_comm[j].unshifted[k].size();
                                }
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_selectors_comm[j].shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.lookup_selectors_comm[j].shifted[k]);
                                }
                            }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k]);
                                }
                            if (params.input.proofs[i].comm.lookup_runtime_comm.unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.lookup_runtime_comm.unshifted[k].size();
                                }
                            for(std::size_t k = 0; k < params.input.proofs[i].comm.lookup_runtime_comm.shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.lookup_runtime_comm.shifted[k]);
                                }
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.selectors_comm.size(); j ++) {
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.selectors_comm[j].unshifted[k].size(); k++) {
                                    unshifted_commitments.push_back(params.input.proofs[i].comm.selectors_comm[j].unshifted[k]);
                                }
                                if (params.input.proofs[i].comm.selectors_comm[j].unshifted.size() > max_size) {
                                    max_size = params.input.proofs[i].comm.selectors_comm[j].unshifted[k].size();
                                }
                                for(std::size_t k = 0; k < params.input.proofs[i].comm.selectors_comm[j].shifted[k].size(); k++) {
                                    shifted_commitments.push_back(params.input.proofs[i].comm.selectors_comm[j].shifted[k]);
                                }
                            }
                            auto f_comm_shifted = msm_component::generate_assignments(assignment, {scalars, shifted_commitments}, row);
                            row+= typename msm_component::rows_amount;
                            std::vector<var_ec_point> f_comm_unshifted; 
                            for(std::size_t j = 0; j < max_size; j ++) {
                                std::vector<var_ec_point> part_unshifted_commitments;
                                std::vector<var> part_scalars;
                                for (std::size_t k = 0; k < size; k++) {
                                    if (j < unshifted_commitments[j].size()){
                                        part_unshifted_commitments.push_back(unshifted_commitments[j][k]);
                                        part_scalars.push_back(scalars[j])
                                    }
                                }
                                auto res = msm_component::generate_assignments(assignment, {part_scalars, part_unshifted_commitments}, row);
                                f_comm_unshifted.push_back(res.sum);
                                row+= typename msm_component::rows_amount;
                            }
                            auto chunked_f_comm_shifted = f_comm_shifted.sum;
                            //to-do: U = zero()
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type U = algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();
                            assignment.witness(W0)[row] = U.X;
                            assignment.witness(W1)[row] = U.Y;
                            std::size_t urow = row;
                            var_ec_point chunked_f_comm_unshifted = {var(0, row, false), var(1, row, false)};
                            row++;

                            for(std::size_t j = 0; j < f_comm_unshifted.size(); j ++) {
                                auto res0 = scalar_mul_component::generate_assignments(assignment, {{chunked_f_comm_unshifted.x, chunked_f_comm_unshifted.y}, params.input.PI.zeta_to_srs_len}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_f_comm_unshifted = {res0.X, res0.Y};
                                auto res1 = add_component::generate_assignments(assignment, {{chunked_f_comm_unshifted.x, chunked_f_comm_unshifted.y}, {f_comm_unshifted[j].x, f_comm_unshifted[j].y}}, row);
                                row+=add_component::rows_amount;
                                chunked_f_comm_unshifted = {res1.X, res1.Y};

                            }
                            auto chunked_t_comm_shifted = scalar_mul_component::generate_assignments(assignment, 
                            {{ params.input.proofs[i].comm.t_comm.shifted.x,  params.input.proofs[i].comm.t_comm.shifted.y}, params.input.PI.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            var_ec_point chunked_t_comm_unshifted = {var(0, urow, false), var(1, urow, false)};;
                            for(std::size_t j = 0; j < params.input.proofs[i].comm.t_comm.unshifted.size(); j++) {
                                auto res0 = scalar_mul_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.x, chunked_t_comm_unshifted.y}, params.input.PI.zeta_to_srs_len}, row);
                                row+=scalar_mul_component::rows_amount;
                                chunked_t_comm_unshifted = {res0.X, res0.Y};
                                auto res1 = add_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.x, chunked_t_comm_unshifted.y},
                                 {params.input.proofs[i].comm.t_comm.unshifted[j].x, params.input.proofs[i].comm.t_comm.unshifted[j].y}}, row);
                                row+=add_component::rows_amount;
                                chunked_t_comm_unshifted = {res1.X, res1.Y};
                            }
                            auto chunk_res_unshifted = scalar_mul_component::generate_assignments(assignment, 
                            {{ chunked_t_comm_unshifted.x,  chunked_t_comm_unshifted.y}, params.input.PI.zeta_to_domain_size_minus_1}, row);
                            row+=scalar_mul_component::rows_amount;
                            typename BlueprintFieldType::value_type minus_1 = -1;
                            auto const_res_unshifted = const_mul_component::generate_assignments(assignment, 
                            {chunk_res_unshifted.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            chunked_t_comm_unshifted = {chunk_res_unshifted.X, const_res_unshifted.output};

                            typename BlueprintFieldType::value_type minus_1 = -1;
                            auto const_res_shifted = const_mul_component::generate_assignments(assignment, 
                            {chunked_t_comm_shifted.sum.Y, minus_1}, row);
                            row+=const_mul_component::rows_amount;
                            auto chunked_t_comm_shifted_res = {chunked_t_comm_shifted.sum.X, const_res_unshifted.output};

                            auto ft_comm_unshifted = add_component::generate_assignments(assignment, {{chunked_t_comm_unshifted.x, chunked_t_comm_unshifted.y},
                                 {chunked_f_comm_unshifted.x, chunked_f_comm_unshifted.y}}, row);
                            row+=add_component::rows_amount;
                            auto ft_comm_shifted = add_component::generate_assignments(assignment, {{chunked_t_comm_shifted_res.x, chunked_t_comm_shifted_res.y},
                                 {chunked_f_comm_shifted.x, chunked_f_comm_shifted.y}}, row);
                            row+=add_component::rows_amount;
                            f_comm ft_comm = {{{ft_comm_shifted.X, ft_comm_shifted.Y}}, {{ft_comm_unshifted.X, ft_comm_unshifted.Y}};

                            std::vector<f_comm> evaluations;
                            evaluations.push_back(params.proofs.comm.p_comm);
                            evaluations.push_back(ft_comm);
                            evaluations.push_back(params.proofs.comm.z_comm);
                            evaluations.push_back(params.proofs.comm.generic_comm);
                            evaluations.push_back(params.proofs.comm.psm_comm);
                            for(std::size_t j = 0; j < params.proofs.comm.oracles_poly_comm; j++){
                                evaluations.push_back(params.proofs.comm.oracles_poly_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.proofs.comm.witness_comm; j++){
                                evaluations.push_back(params.proofs.comm.witness_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.proofs.comm.sigma_comm; j++){
                                evaluations.push_back(params.proofs.comm.sigma_comm[j]);
                            }
                            for(std::size_t j = 0; j < params.proofs.comm.lookup_sorted_comm; j++){
                                evaluations.push_back(params.proofs.comm.lookup_sorted_comm[j]);
                            }
                            evaluations.push_back(params.proofs.comm.lookup_agg_comm);
                            evaluations.push_back(params.proofs.comm.table_comm);
                            evaluations.push_back(params.proofs.comm.lookup_runtime_comm);
                            typename batch_verify_component::params_type::PE evals = {evaluatiions};
                            typename batch_verify_component::params_type::var_proof p = {params.input.proofs[i].transcript, evals,
                             params.input.proofs[i].opening_proof};
                            batch_proofs.push_back(p);
                        }
                        batch_verify_component::public_input pi = {params.input.PI.H, params.input.PI.G, params.input.PI.batch_scalars, params.input.PI.cip};
                        batch_verify_component::params_type batch_params = {batch_proofs, pi};
                        batch_verify_component::generate_assignments(assignment, batch_params, row);
                        row+=batch_verify_component::rows_amount;
                        result_type(component_start_row);
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
                        //std::size_t n_2 = ceil(log2(n));
                        //std::size_t padding = (1 << n_2) - n;
                        typename BlueprintFieldType::integral_type one = 1;
                        //typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type zero = typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type::zero();
                        //assignment.constant(0)[row] = zero.X;
                        //assignment.constant(0)[row + 1] = zero.Y;
                        std::vector<var_ec_point> bases;
                        bases.push_back(params.input.PI.H);
                        for(std::size_t i = 1; i < n + 1; i ++){
                            bases.push_back(params.input.PI.G[i - 1]);
                        }
                        /*for (std::size_t i = n + 1; i < n + 1 + padding; i++) {
                            bases.push_back({var(0, component_start_row + 1, false, var::column_type::constant), var(0, component_start_row + 1, false, var::column_type::constant)});
                        }*/
                        for (std::size_t i = 0; i < batch_size; i++) {
                            var cip = params.input.cip[i];
                            typename sub_component::params_type sub_params = {cip, var(0, start_row_index + 2, false, var::column_type::constant)};
                            zk::components::generate_circuit<sub_component>(bp, assignment, sub_params,
                                                                        start_row_index);
                            typename sub_component::result_type sub_res(sub_params, start_row_index);
                            row = row + sub_component::rows_amount;

                            //params.input.proofs[i].transcript.absorb_assignment(assignment, sub_res.output, row);
                            //U = transcript.squeeze.to_group()
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type U = algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();
                            std::size_t u_row = row;
                            row++;

                            //params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].o.delta.x, row);
                            //params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].o.delta.y, row);
                            bases.push_back(params.input.proofs[i].o.G);
                            bases.push_back({var(0, row), var(1, row)});
                            for (std::size_t j = 0 ; j < lr_rounds; j++) {
                                bases.push_back(params.input.proofs[i].o.L[j]);
                                bases.push_back(params.input.proofs[i].o.R[j]);
                            }
                            std::size_t unshifted_size = 0;
                            std::size_t shifted_size = 0;

                            for (std::size_t j = 0 ; j < comm_size; j++) {
                                unshifted_size = params.input.proofs[i].pe.comm[j].unshifted.size();
                                for (std::size_t k =0; k< unshifted_size; k++){
                                    bases.push_back(params.input.proofs[i].pe.comm[j].unshifted[k]);
                                }
                                shifted_size = params.input.proofs[i].pe.comm[j].shifted.size();
                                for (std::size_t k =0; k< shifted_size; k++){
                                    bases.push_back(params.input.proofs[i].pe.comm[j].shifted[k]);
                                }
                            }
                            bases.push_back({var(0, u_row, false), var(1, u_row, false)});
                            bases.push_back(params.input.proofs[i].o.delta);
                        }
                        auto res = msm_component::generate_circuit(bp, assignment, {params.input.PI.scalars, bases}, row);
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

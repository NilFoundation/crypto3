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
//#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType,
                std::size_t n, std::size_t bases_size,
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

                    using msm_component = zk::components::element_g1_multi_scalar_mul< ArithmetizationType, CurveType, bases_size,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> ;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xff91;

                public:
                    constexpr static const std::size_t rows_amount = 1 + sub_component::rows_amount + msm_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        struct f_comm {
                            std::vector<var_ec_point> shifted;
                            std::vector<var_ec_point> unshifted;
                        };
                        struct PE {
                            std::vector<f_comm> comm;
                        };
                        struct opening_proof {
                            std::vector<var_ec_point> L;
                            std::vector<var_ec_point> R;
                            var_ec_point delta;
                            var_ec_point G;
                        };
                        struct var_proof {
                            /*kimchi_transcript<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                                          W11, W12, W13, W14> transcript;*/
                            PE pe;
                            opening_proof o;
                        };
                        struct public_input {
                            var_ec_point H;
                            std::vector<var_ec_point> G;
                            std::vector<var> scalars;
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
                        //std::size_t n_2 = ceil(log2(n));
                        //std::size_t padding = (1 << n_2) - n;
                        typename BlueprintFieldType::integral_type one = 1;
                        //typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type zero = typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type::zero();
                        //assignment.constant(0)[row] = zero.X;
                        //assignment.constant(0)[row + 1] = zero.Y;
                        assignment.constant(0)[row + 2] = (one << 255);
                        std::vector<var_ec_point> bases;
                        bases.push_back(params.input.PI.H);
                        for(std::size_t i = 1; i < n + 1; i ++){
                            bases.push_back(params.input.PI.G[i - 1]);
                        }
                        /*for (std::size_t i = n + 1; i < n + 1 + padding; i++) {
                            bases.push_back({var(0, component_start_row + 1, false, var::column_type::constant), var(0, component_start_row + 1, false, var::column_type::constant)});
                        }*/
                        for (std::size_t i = 0; i < params.input.proofs.size(); i++) {
                            var cip = params.input.PI.cip[i];
                            typename sub_component::params_type sub_params = {cip, var(0, component_start_row + 2, false, var::column_type::constant)};
                            auto sub_res = sub_component::generate_assignments(assignment, sub_params, row);
                            row = row + sub_component::rows_amount;

                            //params.input.proofs[i].transcript.absorb_assignment(assignment, sub_res.output, row);
                            //U = transcript.squeeze.to_group()
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type U = algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();
                            assignment.witness(W0)[row] = U.X;
                            assignment.witness(W1)[row] = U.Y;
                            std::size_t u_row = row;
                            row++;

                            //params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].o.delta.x, row);
                            //params.input.proofs[i].transcript.absorb_assignment(assignment, params.input.proofs[i].o.delta.y, row);
                            bases.push_back(params.input.proofs[i].o.G);
                            bases.push_back({var(0, row), var(1, row)});
                            for (std::size_t j = 0 ; j < params.input.proofs[i].o.L.size(); j++) {
                                bases.push_back(params.input.proofs[i].o.L[j]);
                                bases.push_back(params.input.proofs[i].o.R[j]);
                            }
                            std::size_t unshifted_size = 0;
                            std::size_t shifted_size = 0;

                            for (std::size_t j = 0 ; j < params.input.proofs[i].pe.comm.size(); j++) {
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
                        auto res = msm_component::generate_assignments(assignment, {params.input.PI.scalars, bases}, row);
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
                        for (std::size_t i = 0; i < params.input.proofs.size(); i++) {
                            var cip = params.input.PI.cip[i];
                            typename sub_component::params_type sub_params = {cip, var(0, row + 2, false, var::column_type::constant)};
                            zk::components::generate_circuit<sub_component>(bp, assignment, sub_params,
                                                                        row);
                            typename sub_component::result_type sub_res(sub_params, row);
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
                            for (std::size_t j = 0 ; j < params.input.proofs[i].o.L.size(); j++) {
                                bases.push_back(params.input.proofs[i].o.L[j]);
                                bases.push_back(params.input.proofs[i].o.R[j]);
                            }
                            std::size_t unshifted_size = 0;
                            std::size_t shifted_size = 0;

                            for (std::size_t j = 0 ; j < params.input.proofs[i].pe.comm.size(); j++) {
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
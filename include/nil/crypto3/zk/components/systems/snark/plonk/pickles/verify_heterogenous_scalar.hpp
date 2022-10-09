//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_SCALAR_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_SCALAR_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // scalar field part of verify_generogenous
                // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/verify.ml#L30
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType, 
                    std::size_t BatchSize, std::size_t list_size, std::size_t... WireIndexes>
                class verify_generogenous_scalar;

                template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,  
                         std::size_t BatchSize, std::size_t list_size, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class verify_generogenous_scalar<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType, KimchiParamsType, BatchSize, list_size,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    constexpr static const std::size_t ScalarSize = 255;

                    using ArithmetizationType = snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using endo_scalar_component = zk::components::endo_scalar<ArithmetizationType, CurveType, ScalarSize, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;
                    using get_domain_generator_component = zk::components::get_domain_generator<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    using to_tick_field_component = zk::components::to_tick_field<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    using combined_evals_component = zk::components::combined_evals<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;
                    
                    using scalars_env_component = zk::components::scalars_env<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    using derive_plonk_component = zk::components::derive_plonk<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    using compute_challenges_component = zk::components::compute_challenges<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    using combined_inner_product_component = zk::components::combined_inner_product<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;
                    
                    using shift_to_field_component = zk::components::shift_to_field<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t poly_size = 4 + (KimchiParamsType::circuit_params::used_lookup ? 1 : 0); 

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<deferred_values, list_size> def_values;
                        std::array<deferred_values, list_size> evals;
                        std::array<deferred_values, list_size> messages_for_next_step_proof;
                        var domain_generator;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        for(std::size_t i = 0; i < list_size; i++) {
                            auto def_values_xi = endo_scalar_component::generate_assignments(assignment, {params.def_values[i].xi}, row).output;
                            row += endo_scalar_component::rows_amount;
                            auto zeta = endo_scalar_component::generate_assignments(assignment, {params.def_values[i].plonk.zeta}, row).output;
                            row += endo_scalar_component::rows_amount;
                            auto alpha = endo_scalar_component::generate_assignments(assignment, {params.def_values[i].plonk.alpha}, row).output;
                            row += endo_scalar_component::rows_amount;
                            auto zetaw = mul_component::generate_assignments(assignment, {zets, params.domain_generator}, row).output;
                            row += mul_component::rows_amount;
                            var min_poly_joint_combiner;
                            if (KimchiParamsType::circuit_params::lookup_used) {
                                min_poly_joint_combiner = endo_scalar_component::generate_assignments(assignment, {params.def_values[i].plonk.joint_combiner}, row).output;
                                row += endo_scalar_component::rows_amount;
                            }
                            std::array<var, poly_size> min_poly;
                            std::array<var, poly_size> plonk0_poly;
                            if (KimchiParamsType::circuit_params::lookup_used) {
                                min_poly = {alpha, params.def_values[i].plonk.beta, params.def_values[i].plonk.gamma, zeta, min_poly_joint_combiner};
                                plonk0_poly = {params.def_values[i].plonk.alpha, params.def_values[i].plonk.beta, params.def_values[i].plonk.gamma, params.def_values[i].plonk.zeta, 
                                params.def_values[i].plonk.joint_combiner};
                            } else {
                                min_poly = {alpha, params.def_values[i].plonk.beta, params.def_values[i].plonk.gamma, zeta};
                                plonk0_poly = {params.def_values[i].plonk.alpha, params.def_values[i].plonk.beta, params.def_values[i].plonk.gamma, params.def_values[i].plonk.zeta};
                            }
                            auto tick_combined_evals = combined_evals_component::generate_assignments(assignment, {params.def_values[i].plonk.gamma}, row).output;
                            row += combined_evals_component::rows_amount;
                            auto tick_env = scalars_env_component::generate_assignments(assignment, {params.def_values.branch_data, min_poly, tick_combined_evals}
                            , row).output;
                            row += scalars_env_component::rows_amount;
                            auto plonk = derive_plonk_component::generate_assignments(assignment, {tick_env, min_poly, plonk0_poly, tick_combined_evals}, row).output;
                            row += derive_plonk_component::rows_amount;
                            auto old_bulletproof_challenges = compute_challenges_component::generate_assignments(assignment, {
                                params.messages_for_next_step_proof[i].old_bulletproof_challenges}, row).output;
                            row += compute_challenges_component::rows_amount;
                            // absorb sequence
                            auto combined_inner_product_actual = combined_inner_product_component::generate_assignments(assignment, {
                                tick_env, min_poly, params.evals[i].ft_eval1, evals[i].evals, r_actual}, row).output;
                            row += combined_inner_product_component::rows_amount;
                            auto bulletproof_challenges = compute_challenges_component::generate_assignments(assignment, {
                                params.def_values[i].bulletproof_challenges}, row).output;
                            row += compute_challenges_component::rows_amount;
                            //get b_actual
                            shifted_combined_inner_product = shift_to_field_component::generate_assignments(assignment, {
                                params.def_values[i].combined_inner_product}, row).output;
                            row += compute_challenges_component::rows_amount;
                            shifted_b = shift_to_field_component::generate_assignments(assignment, {
                                params.def_values[i].b}, row).output;
                            row += compute_challenges_component::rows_amount;
                        }        
                        return result_type();
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row = 0) {
                        // xi xi_actual
                        // shifted_combined_inner_product combined_inner_product_actual
                        // shifted_b b
                        
                    }

                    static void
                        generate_assignments_constant(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFY_HETEROGENOUS_SCALAR_HPP
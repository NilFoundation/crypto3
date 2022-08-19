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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_INDEX_TERMS_BASES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_INDEX_TERMS_BASES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_instances/ec_index_terms.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // constraints scalars (exluding generic constraint)
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L568-L673
                // Input: constraint
                // Output: constraint-related scalar x for linearization
                template<typename ArithmetizationType, typename KimchiParamsType,
                    std::size_t... WireIndexes>
                class index_terms_bases;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename KimchiParamsType,
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
                class index_terms_bases<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    KimchiParamsType,
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
                    W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, KimchiParamsType>;

                    constexpr static const std::size_t selector_seed = 0x0f27;

                    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType, KimchiParamsType, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;


                    constexpr static std::size_t rows() {
                        std::size_t n = 0;
                        if (KimchiParamsType::circuit_params::poseidon_gate) {
                            n += index_terms_list::coefficient_0::rows_amount;
                            n += index_terms_list::coefficient_1::rows_amount;
                            n += index_terms_list::coefficient_2::rows_amount;
                            n += index_terms_list::coefficient_3::rows_amount;
                            n += index_terms_list::coefficient_4::rows_amount;
                            n += index_terms_list::coefficient_5::rows_amount;
                            n += index_terms_list::coefficient_6::rows_amount;
                            n += index_terms_list::coefficient_7::rows_amount;
                            n += index_terms_list::coefficient_8::rows_amount;
                            n += index_terms_list::coefficient_9::rows_amount;
                            n += index_terms_list::coefficient_10::rows_amount;
                            n += index_terms_list::coefficient_11::rows_amount;
                            n += index_terms_list::coefficient_12::rows_amount;
                            n += index_terms_list::coefficient_13::rows_amount;
                            n += index_terms_list::coefficient_14::rows_amount;
                        }

                        if (KimchiParamsType::circuit_params::ec_arithmetic_gates) {
                            n += index_terms_list::var_base_mul::rows_amount;
                            n += index_terms_list::complete_add::rows_amount;
                            n += index_terms_list::endo_mul::rows_amount;
                            n += index_terms_list::endo_mul_scalar::rows_amount;
                        }

                        return n;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var alpha;
                        var beta;
                        var gamma;
                        var joint_combiner;

                        std::array<evaluations_type, KimchiParamsType::eval_points_amount>
                            evaluations;
                    };

                    struct result_type {
                        std::array<var, KimchiParamsType::index_term_size()> output;

                        result_type(std::size_t start_row_index) {
                        }

                        result_type() {
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        std::array<var, KimchiParamsType::index_term_size()> output;

                        std::size_t output_idx = 0;

                        if (KimchiParamsType::circuit_params::poseidon_gate) {
                            output[output_idx++] = index_terms_list::coefficient_0::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[0], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_0::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_1::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[1], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_1::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_2::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[2], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_2::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_3::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[3], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_3::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_4::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[4], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_4::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_5::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[5], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_5::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_6::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[6], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_6::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_7::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[7], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_7::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_8::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[8], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_8::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_9::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[9], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_9::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_10::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[10], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_10::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_11::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[11], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_11::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_12::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[12], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_12::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_13::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[13], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_13::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_14::generate_circuit(bp, assignment, {index_terms_list::coefficient_str[14], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_14::rows_amount;
                        }

                        if (KimchiParamsType::circuit_params::ec_arithmetic_gates) {
                            output[output_idx++] = index_terms_list::var_base_mul::generate_circuit(bp, assignment, {index_terms_list::var_base_mul_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::var_base_mul::rows_amount;

                            output[output_idx++] = index_terms_list::complete_add::generate_circuit(bp, assignment, {index_terms_list::complete_add_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::complete_add::rows_amount;

                            output[output_idx++] = index_terms_list::endo_mul::generate_circuit(bp, assignment, {index_terms_list::endo_mul_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::endo_mul::rows_amount;

                            output[output_idx++] = index_terms_list::endo_mul_scalar::generate_circuit(bp, assignment, {index_terms_list::endo_mul_scalar_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::endo_mul_scalar::rows_amount;
                        }

                        assert(output_idx == KimchiParamsType::index_term_size());
                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.output = output;

                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, KimchiParamsType::index_term_size()> output;

                        std::size_t output_idx = 0;

                        if (KimchiParamsType::circuit_params::poseidon_gate) {
                            output[output_idx++] = index_terms_list::coefficient_0::generate_assignments(assignment, {index_terms_list::coefficient_str[0], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_0::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_1::generate_assignments(assignment, {index_terms_list::coefficient_str[1], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_1::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_2::generate_assignments(assignment, {index_terms_list::coefficient_str[2], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_2::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_3::generate_assignments(assignment, {index_terms_list::coefficient_str[3], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_3::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_4::generate_assignments(assignment, {index_terms_list::coefficient_str[4], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_4::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_5::generate_assignments(assignment, {index_terms_list::coefficient_str[5], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_5::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_6::generate_assignments(assignment, {index_terms_list::coefficient_str[6], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_6::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_7::generate_assignments(assignment, {index_terms_list::coefficient_str[7], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_7::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_8::generate_assignments(assignment, {index_terms_list::coefficient_str[8], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_8::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_9::generate_assignments(assignment, {index_terms_list::coefficient_str[9], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_9::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_10::generate_assignments(assignment, {index_terms_list::coefficient_str[10], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_10::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_11::generate_assignments(assignment, {index_terms_list::coefficient_str[11], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_11::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_12::generate_assignments(assignment, {index_terms_list::coefficient_str[12], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_12::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_13::generate_assignments(assignment, {index_terms_list::coefficient_str[13], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_13::rows_amount;

                            output[output_idx++] = index_terms_list::coefficient_14::generate_assignments(assignment, {index_terms_list::coefficient_str[14], 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::coefficient_14::rows_amount;
                        }

                        if (KimchiParamsType::circuit_params::ec_arithmetic_gates) {
                            output[output_idx++] = index_terms_list::var_base_mul::generate_assignments(assignment, {index_terms_list::var_base_mul_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::var_base_mul::rows_amount;

                            output[output_idx++] = index_terms_list::complete_add::generate_assignments(assignment, {index_terms_list::complete_add_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::complete_add::rows_amount;

                            output[output_idx++] = index_terms_list::endo_mul::generate_assignments(assignment, {index_terms_list::endo_mul_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::endo_mul::rows_amount;

                            output[output_idx++] = index_terms_list::endo_mul_scalar::generate_assignments(assignment, {index_terms_list::endo_mul_scalar_str, 
                                params.alpha, params.beta, params.gamma, params.joint_combiner, params.evaluations}, row).output;
                            row += index_terms_list::endo_mul_scalar::rows_amount;
                        }

                        assert(output_idx == KimchiParamsType::index_term_size());
                        assert(row == start_row_index + rows_amount);

                        result_type res;
                        res.output = output;

                        return res;
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }

                    static void generate_assignments_constants(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_INDEX_TERMS_BASES_HPP
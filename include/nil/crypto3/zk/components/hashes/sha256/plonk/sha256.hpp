//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/plonk/sha256_process.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/plonk/decomposition.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class sha256;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4,
                         std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8>
                class sha256<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                             W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using sha256_process_component =
                        sha256_process<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using decomposition_component =
                        decomposition<ArithmetizationType, BlueprintFieldType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                public:
                    constexpr static const std::size_t rows_amount = sha256_process_component::rows_amount*2 + decomposition_component::rows_amount*2 + 2;
                    constexpr static const std::size_t selector_seed = 0x0f19;
                    constexpr static const std::size_t gates_amount = 1;
                    struct params_type {
                        std::array<var, 4> block_data;
                    };

                    struct result_type {
                        std::array<var, 2> output;

                        result_type(std::size_t component_start_row) {
                            std::array<var, 2> output = {var(W0, component_start_row + rows_amount - 1, false),
                                                         var(W1, component_start_row + rows_amount - 1, false)};
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t component_start_row) {

                        std::size_t row = component_start_row;
                        std::array<var, 2> input_params_1 = {params.block_data[0], params.block_data[1]};
                        typename decomposition_component::params_type decomposition_params = {input_params_1};
                        auto sha_block_part_1 =
                            decomposition_component::generate_circuit(bp, assignment, decomposition_params, row);
                        row += decomposition_component::rows_amount;
                        std::array<var, 2> input_params_2 = {params.block_data[2], params.block_data[3]};
                        decomposition_params = {input_params_2};
                        auto sha_block_part_2 =
                            decomposition_component::generate_circuit(bp, assignment, decomposition_params, row);
                        row += decomposition_component::rows_amount;
                        std::array<var, 16> input_words;
                        for (int i = 0; i < 8; i++) {
                            input_words[i] = sha_block_part_1.output[i];
                            input_words[8 + i] = sha_block_part_2.output[i];
                        }
                        std::array<var, 8> constants_var = {var(0, row, false, var::column_type::constant),
                                                            var(0, row + 1, false, var::column_type::constant),
                                                            var(0, row + 2, false, var::column_type::constant),
                                                            var(0, row + 3, false, var::column_type::constant),
                                                            var(0, row + 4, false, var::column_type::constant),
                                                            var(0, row + 5, false, var::column_type::constant),
                                                            var(0, row + 6, false, var::column_type::constant),
                                                            var(0, row + 7, false, var::column_type::constant)};
                        typename sha256_process_component::params_type sha_params = {constants_var, input_words};
                        auto sha_output = sha256_process_component::generate_circuit(bp, assignment, sha_params, row);
                        row += sha256_process_component::rows_amount;
                        std::array<var, 16> input_words2_var = {var(0, row + 8, false, var::column_type::constant),
                                                             var(0, row + 9, false, var::column_type::constant),
                                                             var(0, row + 10, false, var::column_type::constant),
                                                             var(0, row + 11, false, var::column_type::constant),
                                                             var(0, row + 12, false, var::column_type::constant),
                                                             var(0, row + 13, false, var::column_type::constant),
                                                             var(0, row + 14, false, var::column_type::constant),
                                                             var(0, row + 15, false, var::column_type::constant),
                                                             var(0, row + 16, false, var::column_type::constant),
                                                             var(0, row + 17, false, var::column_type::constant),
                                                             var(0, row + 18, false, var::column_type::constant),
                                                             var(0, row + 19, false, var::column_type::constant),
                                                             var(0, row + 20, false, var::column_type::constant),
                                                             var(0, row + 21, false, var::column_type::constant),
                                                             var(0, row + 22, false, var::column_type::constant),
                                                             var(0, row + 23, false, var::column_type::constant)};
                        typename sha256_process_component::params_type sha_params2 = {sha_output.output_state,
                                                                                      input_words2_var};
                        sha256_process_component::generate_circuit(bp, assignment, sha_params, row);
                        row = row + sha256_process_component::rows_amount;
                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        assignment.enable_selector(first_selector_index, row);
                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        std::array<var, 2> input_params_1 = {params.block_data[0], params.block_data[1]};
                        typename decomposition_component::params_type decomposition_params = {input_params_1};
                        auto sha_block_part_1 =
                            decomposition_component::generate_assignments(assignment, decomposition_params, row);
                        row += decomposition_component::rows_amount;
                        std::array<var, 2> input_params_2 = {params.block_data[2], params.block_data[3]};
                        decomposition_params = {input_params_2};
                        auto sha_block_part_2 =
                            decomposition_component::generate_assignments(assignment, decomposition_params, row);
                        row += decomposition_component::rows_amount;
                        std::array<var, 16> input_words;
                        for (int i = 0; i < 8; i++) {
                            input_words[i] = sha_block_part_1.output[i];
                            input_words[8 + i] = sha_block_part_2.output[i];
                        }
                        std::array<typename ArithmetizationType::field_type::value_type, 8> constants = {
                            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
                        for (int i = 0; i < 8; i++) {
                            assignment.constant(0)[component_start_row + i] = constants[i];
                        }
                        std::array<var, 8> constants_var = {var(0, row, false, var::column_type::constant),
                                                            var(0, row + 1, false, var::column_type::constant),
                                                            var(0, row + 2, false, var::column_type::constant),
                                                            var(0, row + 3, false, var::column_type::constant),
                                                            var(0, row + 4, false, var::column_type::constant),
                                                            var(0, row + 5, false, var::column_type::constant),
                                                            var(0, row + 6, false, var::column_type::constant),
                                                            var(0, row + 7, false, var::column_type::constant)};
                        typename sha256_process_component::params_type sha_params = {constants_var, input_words};
                        auto sha_output = sha256_process_component::generate_assignments(assignment, sha_params, row);
                        row += sha256_process_component::rows_amount;

                        std::array<typename ArithmetizationType::field_type::value_type, 16> input_words2 = {
                            1 << 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 9};
                        for (int i = 0; i < 16; i++) {
                            assignment.constant(0)[component_start_row + 8 + i] = input_words2[i];
                        }
                        std::array<var, 16> input_words2_var = {var(0, row + 8, false, var::column_type::constant),
                                                             var(0, row + 9, false, var::column_type::constant),
                                                             var(0, row + 10, false, var::column_type::constant),
                                                             var(0, row + 11, false, var::column_type::constant),
                                                             var(0, row + 12, false, var::column_type::constant),
                                                             var(0, row + 13, false, var::column_type::constant),
                                                             var(0, row + 14, false, var::column_type::constant),
                                                             var(0, row + 15, false, var::column_type::constant),
                                                             var(0, row + 16, false, var::column_type::constant),
                                                             var(0, row + 17, false, var::column_type::constant),
                                                             var(0, row + 18, false, var::column_type::constant),
                                                             var(0, row + 19, false, var::column_type::constant),
                                                             var(0, row + 20, false, var::column_type::constant),
                                                             var(0, row + 21, false, var::column_type::constant),
                                                             var(0, row + 22, false, var::column_type::constant),
                                                             var(0, row + 23, false, var::column_type::constant)};
                        typename sha256_process_component::params_type sha_params2 = {sha_output.output_state,
                                                                                      input_words2_var};
                        auto sha256_output2 = sha256_process_component::generate_assignments(assignment, sha_params2, row).output_state;
                        row = row + sha256_process_component::rows_amount;
                        typename ArithmetizationType::field_type::integral_type one = 1;
                        for (std::size_t i = 0; i < 8; i ++){
                            assignment.witness(i)[row] = assignment.var_value(sha256_output2[i]);
                        }
                        row++;
                        assignment.witness(W0)[row] = assignment.var_value(sha256_output2[0]) + assignment.var_value(sha256_output2[1]) * (one << 32)
                         + assignment.var_value(sha256_output2[2]) * (one << 64) +
                        assignment.var_value(sha256_output2[3]) * (one << 96);
                        assignment.witness(W1)[row] = assignment.var_value(sha256_output2[4]) + assignment.var_value(sha256_output2[5]) * (one << 32)
                         + assignment.var_value(sha256_output2[6]) * (one << 64) +
                        assignment.var_value(sha256_output2[7]) * (one << 96);
                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const std::size_t first_selector_index) {
                        typename ArithmetizationType::field_type::integral_type one = 1;
                        auto constraint_1 = bp.add_constraint(var(W0, + 1) - (var(W0, 0)+ var(W1, 0) * (one << 32) + var(W2, 0) * (one << 64) +
                        var(W3, 0) * (one << 96)));
                        auto constraint_2 = bp.add_constraint(var(W1, + 1) - (var(W4, 0)+ var(W5, 0) * (one << 32) + var(W6, 0) * (one << 64) +
                        var(W7, 0) * (one << 96)));
                        bp.add_gate(first_selector_index, {constraint_1, constraint_2});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                        std::size_t j = component_start_row;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_SHA256_HPP

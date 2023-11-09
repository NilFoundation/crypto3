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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256_process.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/decomposition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input:
            // Output:
            template<typename ArithmetizationType>
            class sha256;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class sha256<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;
                using sha256_process_type =
                    sha256_process<
                            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
                using decomposition_type =
                    decomposition<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return sha256::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(sha256_process_type::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(decomposition_type::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<nil::blueprint::manifest_param>(
                            new nil::blueprint::manifest_single_value_param(9)),
                        true
                    ).merge_with(sha256_process_type::get_manifest())
                    .merge_with(decomposition_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return
                        2 * sha256_process_type::get_rows_amount(witness_amount, lookup_column_amount) +
                        2 * decomposition_type::get_rows_amount(witness_amount, lookup_column_amount) +
                        2;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    std::array<var, 4> block_data;

                    std::vector<var> all_vars() const {
                        return {block_data[0], block_data[1], block_data[2], block_data[3]};
                    }
                };

                struct result_type {
                    std::array<var, 2> output;

                    result_type(const sha256 &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + component.rows_amount - 1, false),
                                  var(component.W(1), start_row_index + component.rows_amount - 1, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output[0], output[1]};
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                sha256(WitnessContainerType witness, ConstantContainerType constant,
                       PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                sha256(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                       std::initializer_list<typename component_type::constant_container_type::value_type>
                           constants,
                       std::initializer_list<typename component_type::public_input_container_type::value_type>
                           public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                using lookup_table_definition = typename
                    nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables(){
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {};

                    auto sparse_values_base4 = std::shared_ptr<lookup_table_definition>(new typename sha256_process_type::sparse_values_base4_table());
                    result.push_back(sparse_values_base4);

                    auto sparse_values_base7 = std::shared_ptr<lookup_table_definition>(new typename sha256_process_type::sparse_values_base7_table());
                    result.push_back(sparse_values_base7);

                    auto maj = std::shared_ptr<lookup_table_definition>(new typename sha256_process_type::maj_function_table());
                    result.push_back(maj);

                    auto reverse_sparse_sigmas_base4 = std::shared_ptr<lookup_table_definition>(new typename sha256_process_type::reverse_sparse_sigmas_base4_table());
                    result.push_back(reverse_sparse_sigmas_base4);

                    auto reverse_sparse_sigmas_base7 = std::shared_ptr<lookup_table_definition>(new typename sha256_process_type::reverse_sparse_sigmas_base7_table());
                    result.push_back(reverse_sparse_sigmas_base7);

                    auto ch = std::shared_ptr<lookup_table_definition>(new typename sha256_process_type::ch_function_table());
                    result.push_back(ch);

                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables["sha256_sparse_base4/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_sparse_base4/first_column"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_reverse_sparse_base4/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_sparse_base7/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_sparse_base7/first_column"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_reverse_sparse_base7/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_maj/full"] = 0; // REQUIRED_TABLE
                    lookup_tables["sha256_ch/full"] = 0; // REQUIRED_TABLE

                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_sha256 =
                sha256<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using var = typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::var;
                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = plonk_sha256<BlueprintFieldType, ArithmetizationParams>;
                using sha256_process_type = typename component_type::sha256_process_type;
                using decomposition_type = typename component_type::decomposition_type;

                decomposition_type decomposition_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {}, {});

                std::array<var, 2> input_1 = {instance_input.block_data[0], instance_input.block_data[1]};
                typename decomposition_type::input_type decomposition_input = {input_1};
                typename decomposition_type::result_type sha_block_part_1 =
                    generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                row += decomposition_instance.rows_amount;

                std::array<var, 2> input_2 = {instance_input.block_data[2], instance_input.block_data[3]};
                decomposition_input = {input_2};

                typename decomposition_type::result_type sha_block_part_2 =
                    generate_assignments(decomposition_instance, assignment, decomposition_input, row);
                row += decomposition_instance.rows_amount;

                sha256_process<ArithmetizationType> sha256_process_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {component.C(0)}, {});

                std::array<var, 16> input_words_vars;
                for (int i = 0; i < 8; i++) {
                    input_words_vars[i] = sha_block_part_1.output[i];
                    input_words_vars[8 + i] = sha_block_part_2.output[i];
                }

                std::array<var, 8> constants_vars = {
                    var(component.C(0), start_row_index, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 2, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 3, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 4, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 5, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 6, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 7, false, var::column_type::constant)};

                typename sha256_process<ArithmetizationType>::input_type sha256_process_input = {
                    constants_vars, input_words_vars};

                std::array<var, 8> first_block_state =
                    generate_assignments(sha256_process_instance, assignment, sha256_process_input, row).output_state;
                row += sha256_process_instance.rows_amount;

                std::array<var, 16> input_words2_vars = {
                    var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 15, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 16, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 17, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 18, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 19, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 20, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 21, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 22, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                typename sha256_process<ArithmetizationType>::input_type sha256_process_input_2 = {
                    first_block_state, input_words2_vars};

                std::array<var, 8> second_block_state =
                    generate_assignments(sha256_process_instance, assignment, sha256_process_input_2, row).output_state;

                row += sha256_process_instance.rows_amount;
                typename ArithmetizationType::field_type::integral_type one = 1;
                for (std::size_t i = 0; i < 8; i++) {
                    assignment.witness(component.W(i), row) = var_value(assignment, second_block_state[i]);
                }

                row++;

                assignment.witness(component.W(1), row) = var_value(assignment, second_block_state[7]) +
                                                          var_value(assignment, second_block_state[6]) * (one << 32) +
                                                          var_value(assignment, second_block_state[5]) * (one << 64) +
                                                          var_value(assignment, second_block_state[4]) * (one << 96);
                assignment.witness(component.W(0), row) = var_value(assignment, second_block_state[3]) +
                                                          var_value(assignment, second_block_state[2]) * (one << 32) +
                                                          var_value(assignment, second_block_state[1]) * (one << 64) +
                                                          var_value(assignment, second_block_state[0]) * (one << 96);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input) {

                using var = typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::var;

                typename BlueprintFieldType::integral_type one = 1;
                auto constraint_1 =
                    var(component.W(1), +1) -
                    (var(component.W(7), 0) + var(component.W(6), 0) * (one << 32) +
                     var(component.W(5), 0) * (one << 64) + var(component.W(4), 0) * (one << 96));
                auto constraint_2 =
                    var(component.W(0), +1) -
                    (var(component.W(3), 0) + var(component.W(2), 0) * (one << 32) +
                     var(component.W(1), 0) * (one << 64) + var(component.W(0), 0) * (one << 96));
                return bp.add_gate({constraint_1, constraint_2});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t row = start_row_index;

                using var = typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::var;
                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using component_type = plonk_sha256<BlueprintFieldType, ArithmetizationParams>;
                using sha256_process_type = typename component_type::sha256_process_type;
                using decomposition_type = typename component_type::decomposition_type;

                generate_assignments_constant(component, bp, assignment, instance_input, row);

                decomposition_type decomposition_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {}, {});

                std::array<var, 2> input_1 = {instance_input.block_data[0], instance_input.block_data[1]};
                typename decomposition_type::input_type decomposition_input = {
                    input_1};
                typename decomposition_type::result_type sha_block_part_1 =
                    generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                row += decomposition_instance.rows_amount;

                std::array<var, 2> input_2 = {instance_input.block_data[2], instance_input.block_data[3]};
                decomposition_input = {input_2};
                typename decomposition_type::result_type sha_block_part_2 =
                    generate_circuit(decomposition_instance, bp, assignment, decomposition_input, row);
                row += decomposition_instance.rows_amount;

                sha256_process_type sha256_process_instance(
                    {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4), component.W(5),
                     component.W(6), component.W(7), component.W(8)},
                    {component.C(0)}, {});

                std::array<var, 16> input_words_vars;
                for (int i = 0; i < 8; i++) {
                    input_words_vars[i] = sha_block_part_1.output[i];
                    input_words_vars[8 + i] = sha_block_part_2.output[i];
                }
                std::array<var, 8> constants_vars = {var(component.C(0), start_row_index, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 1, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 2, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 3, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 4, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 5, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 6, false, var::column_type::constant),
                                                     var(component.C(0), start_row_index + 7, false, var::column_type::constant)};

                typename sha256_process_type::input_type sha256_process_input = {
                    constants_vars, input_words_vars};
                typename sha256_process_type::result_type first_block_state =
                    generate_circuit(sha256_process_instance, bp, assignment, sha256_process_input, row);

                row += sha256_process_instance.rows_amount;
                std::array<var, 16> input_words2_vars = {
                    var(component.C(0), start_row_index + 8, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 9, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 10, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 11, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 12, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 13, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 14, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 15, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 16, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 17, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 18, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 19, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 20, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 21, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 22, false, var::column_type::constant),
                    var(component.C(0), start_row_index + 23, false, var::column_type::constant)};

                typename sha256_process_type::input_type sha256_process_input_2 = {
                    first_block_state.output_state, input_words2_vars};

                generate_circuit(sha256_process_instance, bp, assignment, sha256_process_input_2, row);

                row = row + sha256_process_instance.rows_amount;
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, row);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_sha256<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_sha256<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                std::array<typename BlueprintFieldType::value_type, 8> constants = {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                };
                for (int i = 0; i < constants.size(); i++) {
                    assignment.constant(component.C(0), start_row_index + i) = constants[i];
                }

                std::array<typename BlueprintFieldType::value_type, 16> constants2 = {
                    2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 9
                };
                for (int i = 0; i < constants2.size(); i++) {
                    assignment.constant(component.C(0), start_row_index + constants.size() + i) = constants2[i];
                }
            }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class input_type_converter<plonk_sha256<BlueprintFieldType, ArithmetizationParams>> {

                using component_type = plonk_sha256<BlueprintFieldType, ArithmetizationParams>;
                using input_type = typename component_type::input_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            public:
                static input_type convert(
                    const input_type &input,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &tmp_assignment) {
                    for (std::size_t i = 0; i < 4; i++) {
                        tmp_assignment.public_input(0, i) = var_value(assignment, input.block_data[i]);
                    }

                    input_type new_input;
                    for (std::size_t i = 0; i < 4; i++) {
                        new_input.block_data[i] = var(0, i, false, var::column_type::public_input);
                    }

                    return new_input;
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    return input.block_data[variable.rotation];
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class result_type_converter<plonk_sha256<BlueprintFieldType, ArithmetizationParams>> {

                using component_type = plonk_sha256<BlueprintFieldType, ArithmetizationParams>;
                using result_type = typename component_type::result_type;
                using input_type = typename component_type::input_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, ArithmetizationParams, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    new_result.output[0] =
                        component.move_var(
                            old_result.output[0],
                            start_row_index + component.line_mapping[old_result.output[0].rotation],
                            instance_input);
                    new_result.output[1] =
                        component.move_var(
                            old_result.output[1],
                            start_row_index + component.line_mapping[old_result.output[1].rotation],
                            instance_input);

                    return new_result;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_SHA256_HPP

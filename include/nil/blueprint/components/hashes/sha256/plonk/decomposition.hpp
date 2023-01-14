//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the DECOMPOSITION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DECOMPOSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DECOMPOSITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input:
            // Output:
            template<typename ArithmetizationType, typename FieldType, std::uint32_t WitnessesAmount>
            class decomposition;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class decomposition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, 9>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 9, 0, 0> {

                constexpr static const std::uint32_t WitnessAmount = 9;

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount, 0, 0>;

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t rows_amount = 3;
                const std::size_t gates_amount = 1;

                struct input_type {
                    std::array<var, 2> data;
                };

                struct result_type {
                    std::array<var, 8> output;

                    result_type(const decomposition &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + 1, false),
                                  var(component.W(1), start_row_index + 1, false),
                                  var(component.W(2), start_row_index + 1, false),
                                  var(component.W(3), start_row_index + 1, false),
                                  var(component.W(4), start_row_index + 1, false),
                                  var(component.W(5), start_row_index + 1, false),
                                  var(component.W(6), start_row_index + 1, false),
                                  var(component.W(7), start_row_index + 1, false)};
                    }
                };

                template<typename ContainerType>
                decomposition(ContainerType witness) : component_type(witness, {}, {}) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                decomposition(WitnessContainerType witness, ConstantContainerType constant,
                              PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                decomposition(std::initializer_list<typename component_type::witness_container_type::value_type>
                                  witnesses,
                              std::initializer_list<typename component_type::constant_container_type::value_type>
                                  constants,
                              std::initializer_list<typename component_type::public_input_container_type::value_type>
                                  public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessAmount>
            using plonk_native_decomposition =
                decomposition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, WitnessAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                generate_assignments(
                    const plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::array<typename BlueprintFieldType::integral_type, 2> data = {
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.data[0]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.data[1]).data)};
                std::array<typename BlueprintFieldType::integral_type, 16> range_chunks;
                std::size_t shift = 0;

                for (std::size_t i = 0; i < 8; i++) {
                    range_chunks[i] = (data[0] >> shift) & ((1 << 16) - 1);
                    assignment.witness(component.W(i), row) = range_chunks[i];
                    range_chunks[i + 8] = (data[1] >> shift) & ((1 << 16) - 1);
                    assignment.witness(component.W(i), row + 2) = range_chunks[i + 8];
                    shift += 16;
                }

                assignment.witness(component.W(8), row) = data[0];
                assignment.witness(component.W(8), row + 2) = data[1];

                assignment.witness(component.W(0), row + 1) = range_chunks[1] * (1 << 16) + range_chunks[0];
                assignment.witness(component.W(1), row + 1) = range_chunks[3] * (1 << 16) + range_chunks[2];
                assignment.witness(component.W(2), row + 1) = range_chunks[5] * (1 << 16) + range_chunks[4];
                assignment.witness(component.W(3), row + 1) = range_chunks[7] * (1 << 16) + range_chunks[6];
                assignment.witness(component.W(4), row + 1) = range_chunks[9] * (1 << 16) + range_chunks[8];
                assignment.witness(component.W(5), row + 1) = range_chunks[11] * (1 << 16) + range_chunks[10];
                assignment.witness(component.W(6), row + 1) = range_chunks[13] * (1 << 16) + range_chunks[12];
                assignment.witness(component.W(7), row + 1) = range_chunks[15] * (1 << 16) + range_chunks[14];

                return typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_gates(
                const plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::var;

                std::size_t selector_index = first_selector_index;

                auto constraint_1 = bp.add_constraint(
                    var(component.W(8), -1) - (var(component.W(0), 0) + var(component.W(1), 0) * 0x100000000_cppui255 +
                                               var(component.W(2), 0) * 0x10000000000000000_cppui255 +
                                               var(component.W(3), 0) * 0x1000000000000000000000000_cppui255));
                auto constraint_2 = bp.add_constraint(
                    var(component.W(8), 1) - (var(component.W(4), 0) + var(component.W(5), 0) * 0x100000000_cppui255 +
                                              var(component.W(6), 0) * 0x10000000000000000_cppui255 +
                                              var(component.W(7), 0) * 0x1000000000000000000000000_cppui255));
                auto constraint_3 = bp.add_constraint(var(component.W(0), 0) -
                                                      (var(component.W(0), -1) + var(component.W(1), -1) * (1 << 16)));
                auto constraint_4 = bp.add_constraint(var(component.W(1), 0) -
                                                      (var(component.W(2), -1) + var(component.W(3), -1) * (1 << 16)));
                auto constraint_5 = bp.add_constraint(var(component.W(2), 0) -
                                                      (var(component.W(4), -1) + var(component.W(5), -1) * (1 << 16)));
                auto constraint_6 = bp.add_constraint(var(component.W(3), 0) -
                                                      (var(component.W(6), -1) + var(component.W(7), -1) * (1 << 16)));
                auto constraint_7 = bp.add_constraint(var(component.W(4), 0) -
                                                      (var(component.W(0), +1) + var(component.W(1), +1) * (1 << 16)));
                auto constraint_8 = bp.add_constraint(var(component.W(5), 0) -
                                                      (var(component.W(2), +1) + var(component.W(3), +1) * (1 << 16)));
                auto constraint_9 = bp.add_constraint(var(component.W(6), 0) -
                                                      (var(component.W(4), +1) + var(component.W(5), +1) * (1 << 16)));
                auto constraint_10 = bp.add_constraint(var(component.W(7), 0) -
                                                       (var(component.W(6), +1) + var(component.W(7), +1) * (1 << 16)));
                bp.add_gate(selector_index,
                            {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                             constraint_7, constraint_8, constraint_9, constraint_10});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                generate_circuit(
                    const plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::size_t j = start_row_index + 1;
                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, j);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_native_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DECOMPOSITION_HPP

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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_DECOMPOSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_DECOMPOSITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType, std::uint32_t WitnessesAmount>
            class bit_decomposition;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, 9> : public plonk_component<BlueprintFieldType, ArithmetizationParams, 9, 0, 0> {

                constexpr static const std::uint32_t WitnessesAmount = 9;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t rows_amount = 33;

                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    var k;
                };

                struct result_type {
                    std::array<var, 253> output;
                    result_type(const bit_decomposition &component, std::uint32_t start_row_index) {
                        std::size_t row = start_row_index;
                        for (std::size_t i = 0; i < 11; i++) {
                            if (i != 0) {
                                output[25 * i - 22] = var(component.W(0), row);
                            }
                            if (i != 0) {
                                output[25 * i + 1 - 22] = var(component.W(1), row);
                            }
                            if (i != 0) {
                                output[25 * i + 2 - 22] = var(component.W(2), row);
                            }
                            if (i != 0) {
                                output[25 * i + 3 - 22] = var(component.W(3), row);
                            }
                            if (i != 0) {
                                output[25 * i + 4 - 22] = var(component.W(4), row);
                            }
                            if (i != 0) {
                                output[25 * i + 5 - 22] = var(component.W(5), row);
                            }
                            if (i != 0) {
                                output[25 * i + 6 - 22] = var(component.W(6), row);
                            }
                            if (i != 0) {
                                output[25 * i + 7 - 22] = var(component.W(7), row);
                            }
                            row++;
                            if (i != 0) {
                                output[25 * i + 8 - 22] = var(component.W(0), row);
                            }
                            if (i != 0) {
                                output[25 * i + 9 - 22] = var(component.W(1), row);
                            }
                            if (i != 0) {
                                output[25 * i + 10 - 22] = var(component.W(2), row);
                            }
                            if (i != 0) {
                                output[25 * i + 11 - 22] = var(component.W(3), row);
                            }
                            if (i != 0) {
                                output[25 * i + 12 - 22] = var(component.W(4), row);
                            }
                            if (i != 0) {
                                output[25 * i + 13 - 22] = var(component.W(5), row);
                            }
                            if (i != 0) {
                                output[25 * i + 14 - 22] = var(component.W(6), row);
                            }
                            if (i != 0) {
                                output[25 * i + 15 - 22] = var(component.W(7), row);
                            }
                            row++;
                            if (i != 0) {
                                output[25 * i + 16 - 22] = var(component.W(0), row);
                            }
                            if (i != 0) {
                                output[25 * i + 17 - 22] = var(component.W(1), row);
                            }
                            if (i != 0) {
                                output[25 * i + 18 - 22] = var(component.W(2), row);
                            }
                            if (i != 0) {
                                output[25 * i + 19 - 22] = var(component.W(3), row);
                            }
                            if (i != 0) {
                                output[25 * i + 20 - 22] = var(component.W(4), row);
                            }
                            if (i != 0) {
                                output[25 * i + 21 - 22] = var(component.W(5), row);
                            }
                            output[25 * i] = var(component.W(6), row);
                            output[25 * i + 1] = var(component.W(7), row);
                            output[25 * i + 2] = var(component.W(8), row);
                            row++;
                        }
                    }
                };

                template<typename ContainerType>
                bit_decomposition(ContainerType witness) : component_type(witness, {}, {}) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_decomposition(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                bit_decomposition(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount>
            using plonk_bit_decomposition = bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                generate_assignments(
                    const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using var = typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::var;

                std::size_t row = start_row_index;
                assignment.constant(0, row) = ArithmetizationType::field_type::value_type::zero();
                const std::size_t scalar_size = 275;
                std::array<bool, scalar_size> b = {false};
                typename BlueprintFieldType::integral_type integral_k =
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.k).data);
                for (std::size_t i = 0; i < scalar_size; i++) {
                    b[scalar_size - i - 1] = crypto3::multiprecision::bit_test(integral_k, i);
                }
                typename BlueprintFieldType::integral_type n = 0;
                typename BlueprintFieldType::integral_type t = 0;
                for (std::size_t i = 0; i < 11; i++) {
                    assignment.witness(component.W(0), row) = b[25 * i];
                    if (i != 0) {
                        t = t * 2 + b[25 * i];
                    }
                    assignment.witness(component.W(1), row) = b[25 * i + 1];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 1];
                    }
                    assignment.witness(component.W(2), row) = b[25 * i + 2];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 2];
                    }
                    assignment.witness(component.W(3), row) = b[25 * i + 3];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 3];
                    }
                    assignment.witness(component.W(4), row) = b[25 * i + 4];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 4];
                    }
                    assignment.witness(component.W(5), row) = b[25 * i + 5];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 5];
                    }
                    assignment.witness(component.W(6), row) = b[25 * i + 6];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 6];
                    }
                    assignment.witness(component.W(7), row) = b[25 * i + 7];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 7];
                    }
                    assignment.witness(component.W(8), row) = n;
                    row++;

                    assignment.witness(component.W(0), row) = b[25 * i + 8];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 8];
                    }
                    assignment.witness(component.W(1), row) = b[25 * i + 9];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 9];
                    }
                    assignment.witness(component.W(2), row) = b[25 * i + 10];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 10];
                    }
                    assignment.witness(component.W(3), row) = b[25 * i + 11];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 11];
                    }
                    assignment.witness(component.W(4), row) = b[25 * i + 12];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 12];
                    }
                    assignment.witness(component.W(5), row) = b[25 * i + 13];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 13];
                    }
                    assignment.witness(component.W(6), row) = b[25 * i + 14];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 14];
                    }
                    assignment.witness(component.W(7), row) = b[25 * i + 15];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 15];
                    }
                    row++;

                    assignment.witness(component.W(0), row) = b[25 * i + 16];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 16];
                    }
                    assignment.witness(component.W(1), row) = b[25 * i + 17];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 17];
                    }
                    assignment.witness(component.W(2), row) = b[25 * i + 18];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 18];
                    }
                    assignment.witness(component.W(3), row) = b[25 * i + 19];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 19];
                    }
                    assignment.witness(component.W(4), row) = b[25 * i + 20];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 20];
                    }
                    assignment.witness(component.W(5), row) = b[25 * i + 21];
                    if (i != 0) {
                        t = t * 2 + b[25 * i + 21];
                    }
                    assignment.witness(component.W(6), row) = b[25 * i + 22];
                    t = t * 2 + b[25 * i + 22];
                    assignment.witness(component.W(7), row) = b[25 * i + 23];
                    t = t * 2 + b[25 * i + 23];
                    assignment.witness(component.W(8), row) = b[25 * i + 24];
                    t = t * 2 + b[25 * i + 24];
                    n = t;
                    assignment.witness(component.W(8), row - 1) = n;
                    row++;
                }

                return typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_gates(
                const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::var;

                crypto3::zk::snark::plonk_constraint<BlueprintFieldType> t = var(component.W(8), -1);
                t = t * 2 + var(component.W(0), -1);
                t = t * 2 + var(component.W(1), -1);
                t = t * 2 + var(component.W(2), -1);
                t = t * 2 + var(component.W(3), -1);
                t = t * 2 + var(component.W(4), -1);
                t = t * 2 + var(component.W(5), -1);
                t = t * 2 + var(component.W(6), -1);
                t = t * 2 + var(component.W(7), -1);
                t = t * 2 + var(component.W(0), 0);
                t = t * 2 + var(component.W(1), 0);
                t = t * 2 + var(component.W(2), 0);
                t = t * 2 + var(component.W(3), 0);
                t = t * 2 + var(component.W(4), 0);
                t = t * 2 + var(component.W(5), 0);
                t = t * 2 + var(component.W(6), 0);
                t = t * 2 + var(component.W(7), 0);
                t = t * 2 + var(component.W(0), 1);
                t = t * 2 + var(component.W(1), 1);
                t = t * 2 + var(component.W(2), 1);
                t = t * 2 + var(component.W(3), 1);
                t = t * 2 + var(component.W(4), 1);
                t = t * 2 + var(component.W(5), 1);
                t = t * 2 + var(component.W(6), 1);
                t = t * 2 + var(component.W(7), 1);
                t = t * 2 + var(component.W(8), 1);
                auto constraint_1 = bp.add_constraint(var(component.W(8), 0) - t);
                bp.add_gate(first_selector_index,
                            {constraint_1

                            });
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::var;

                std::size_t row = start_row_index;
                bp.add_copy_constraint({var(component.W(8), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});

                bp.add_copy_constraint({var(component.W(0), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(1), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(2), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(3), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(4), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(5), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(6), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(7), (std::int32_t)(row), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(0), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(1), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(2), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(3), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(4), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(5), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(6), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(7), (std::int32_t)(row + 1), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(0), (std::int32_t)(row + 2), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(1), (std::int32_t)(row + 2), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(2), (std::int32_t)(row + 2), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(3), (std::int32_t)(row + 2), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(4), (std::int32_t)(row + 2), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint({var(component.W(5), (std::int32_t)(row + 2), false),
                                        var(component.W(0), (std::int32_t)(row), false, var::column_type::constant)});
                bp.add_copy_constraint(
                    {var(component.W(8), (std::int32_t)(row + component.rows_amount - 2), false), instance_input.k});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                generate_circuit(
                    const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                std::size_t row = start_row_index;
                assignment.enable_selector(first_selector_index, row + 1, row + component.rows_amount - 2, 3);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
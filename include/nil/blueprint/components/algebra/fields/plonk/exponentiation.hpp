//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_EXPONENTIATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_EXPONENTIATION_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
        namespace blueprint {
            namespace components {

                // Input: exponent, base \in Fp
                // Output: base**exponent
                template<typename ArithmetizationType, typename FieldType, std::size_t ExponentSize, std::uint32_t WitnessesAmount>
                class exponentiation;

                // clang-format off
                // res = base.pow(exponent)
// _______________________________________________________________________________________________________________________________________________
// | W0   | W1             | W2             | W3             | W4            | W5           | W6  | W7  | W8  | W9  | W10 | W11 | W12 | W13 | W14 |
// | base | n = [b0...b7]  | base^[b0b1]    | base^[b0b1b2b3]| base^[b0...b5]|base^[b0...b7]| -   | b7  | b6  | b5  | b4  | b3  | b2  | b1  | b0  |
// | base | n = [b8...b15] | base^[b0...b9] | base^[b0...b11]| ...           | ...          | -   | b15 | b14 | b13 | b12 | b11 | b10 | b9  | b8  |
// | ...                                                                                                                                          |
// | ...  | ...            | ...            | ...            | ...           | ...          | res | ... | ... | ... | ... | ... | ... | ... | ... |
// ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
                // clang-format on

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize>
                class exponentiation<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType,
                    ExponentSize,
                    15
                >:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0> {
                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0>;


                    constexpr static const std::size_t witness_amount = 15;
                    constexpr static const std::size_t reserved_witnesses = 2;    // base, accumulated_n
                public:
                    using var = typename component_type::var;
                    constexpr static const std::size_t intermediate_start = 0 + reserved_witnesses;
                    constexpr static const std::size_t bits_per_intermediate_result =
                        2;    // defines
                              // max degree of the constraints
                              // 2 ** bits_per_intermediate_result
                    constexpr static const std::size_t intermediate_results_per_row =
                        (witness_amount - reserved_witnesses) / (bits_per_intermediate_result + 1);
                    constexpr static const std::size_t bits_per_row =
                        intermediate_results_per_row * bits_per_intermediate_result;
                    constexpr static const std::size_t main_rows = (ExponentSize + bits_per_row - 1) / bits_per_row;
                    constexpr static const std::size_t padded_exponent_size = main_rows * bits_per_row;

                    constexpr static const std::size_t rows_amount = 1 + main_rows;
                    constexpr static const std::size_t gates_amount = 1;

                    struct input_type {
                        var base;
                        var exponent;
                    };

                    struct result_type {
                        var output = var(0, 0);

                        result_type(const exponentiation &component, input_type &params, std::size_t start_row_index) {
                            output = var(component.W(intermediate_start + intermediate_results_per_row - 1),
                                         start_row_index + rows_amount - 1, false);
                        }

                        result_type(const exponentiation &component, std::size_t start_row_index) {
                            output = var(component.W(intermediate_start + intermediate_results_per_row - 1),
                                         start_row_index + rows_amount - 1, false);
                        }
                    };

                    template <typename ContainerType>
                        exponentiation(ContainerType witness):
                            component_type(witness, {}, {}){};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                        exponentiation(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                            component_type(witness, constant, public_input){};

                    exponentiation(
                        std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                            component_type(witnesses, constants, public_inputs){};

                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize, std::uint32_t WitnessesAmount>
                using plonk_exponentiation =
                    exponentiation<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType,
                        ExponentSize,
                        15
                    >;

                    template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize>
                    typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::result_type
                        generate_circuit(
                        const plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::input_type instance_input,
                        const std::uint32_t start_row_index) {
                        auto selector_iterator = assignment.find_selector(component);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                            generate_gates(component, bp, assignment, instance_input, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index + 1, start_row_index + 1 + component.main_rows - 1);

                        generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                        generate_assignments_constants(component, bp, assignment, instance_input, first_selector_index);

                        return typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::result_type(component, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize>
                    typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::result_type
                        generate_assignments(
                        const plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15> &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                        using component_type = plonk_exponentiation<BlueprintFieldType, ArithmetizationParams,
                                                                    ExponentSize, 15>;
                        typename BlueprintFieldType::value_type base = var_value(assignment, instance_input.base);
                        typename BlueprintFieldType::value_type exponent = var_value(assignment, instance_input.exponent);

                        typename BlueprintFieldType::integral_type integral_exp =
                            typename BlueprintFieldType::integral_type(exponent.data);

                        std::array<bool, component_type::padded_exponent_size> bits = {false};
                        // {
                        //     nil::marshalling::status_type status;
                        //     std::array<bool, 255> bits_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_exp, status);
                        //     std::copy(bits_all.end() - padded_exponent_size, bits_all.end(), bits.begin());
                        // }
                        {
                            std::vector<bool> bbb;
                            auto data = exponent.data;
                            while (data != 0) {
                                bbb.push_back((data - (data >> 1 << 1)) != 0);
                                data = data >> 1;
                            }
                            for (int i = 1; i < component_type::padded_exponent_size - bbb.size(); ++i) {
                                bits[i] = false;
                            }
                            for (int i = 0; i < bbb.size(); ++i) {
                                bits[component_type::padded_exponent_size - 1 - i] = bbb[i];
                            }
                        }

                        typename BlueprintFieldType::value_type accumulated_n = 0;
                        typename BlueprintFieldType::value_type acc1 = 1;

                        // we use first empty row to unify first row gate with others
                        assignment.witness(component.W(1), start_row_index) = 0;
                        assignment.witness(component.intermediate_start + component.intermediate_results_per_row - 1, start_row_index) = 1;
                        std::size_t start_row_padded = start_row_index + 1;

                        std::size_t current_bit = 0;
                        for (std::size_t row = start_row_padded; row < start_row_padded + component.main_rows; row++) {
                            assignment.witness(component.W(0), row) = base;

                            for (std::size_t j = 0; j < component.intermediate_results_per_row; j++) {
                                typename BlueprintFieldType::value_type intermediate_exponent = 0;
                                for (std::size_t bit_column = 0; bit_column < component.bits_per_intermediate_result;
                                     bit_column++) {
                                    std::size_t column_idx = 14 - j * (component.bits_per_intermediate_result)-bit_column;
                                    assignment.witness(component.W(column_idx), row) = bits[current_bit] ? 1 : 0;
                                    // wierd stuff is here for oracles scalar
                                    // std::cout<<"column_idx "<<column_idx<<" row "<<row<<" value "<<bits[current_bit]<<std::endl;

                                    intermediate_exponent = 2 * intermediate_exponent + bits[current_bit];

                                    acc1 = acc1 * acc1;
                                    if (bits[current_bit]) {
                                        acc1 = acc1 * base;
                                    }

                                    current_bit++;
                                }
                                accumulated_n =
                                    (accumulated_n * (1 << component.bits_per_intermediate_result)) + intermediate_exponent;
                                assignment.witness(component.W(component.intermediate_start + j), row) = acc1;
                            }
                            assignment.witness(component.W(1), row) = accumulated_n;
                        }

                        return typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::result_type(component, start_row_index);

                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize>
                        void generate_gates(
                        const plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::input_type instance_input,
                        const std::size_t first_selector_index) {

                    	using var = typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::var;

                        typename BlueprintFieldType::value_type exponent_shift = 2;
                        exponent_shift = power(exponent_shift, component.bits_per_row);

                        std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> constraints;

                        nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType> accumulated_n_constraint;
                        for (std::size_t j = 0; j < component.intermediate_results_per_row; j++) {
                            nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType> intermediate_result_constraint =
                                j == 0 ? var(component.W(component.intermediate_start + component.intermediate_results_per_row - 1), -1) :
                                         var(component.W(component.intermediate_start + j - 1), 0);

                            for (std::size_t bit_column = 0; bit_column < component.bits_per_intermediate_result; bit_column++) {
                                std::size_t column_idx = 14 - j * (component.bits_per_intermediate_result)-bit_column;
                                nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType> bit_check_constraint = bp.add_bit_check(var(component.W(column_idx), 0));
                                constraints.push_back(bit_check_constraint); // fail on oracles scalar

                                nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType> bit_res = var(component.W(0), 0) * var(component.W(column_idx), 0);
                                if (j == 0 && bit_column == 0) {
                                    accumulated_n_constraint = var(component.W(column_idx), 0);
                                } else {
                                    accumulated_n_constraint = 2 * accumulated_n_constraint + var(component.W(column_idx), 0);
                                }
                                intermediate_result_constraint = intermediate_result_constraint *
                                                                 intermediate_result_constraint *
                                                                 (bit_res + (1 - var(component.W(column_idx), 0)));
                            }

                            intermediate_result_constraint =
                                intermediate_result_constraint - var(component.W(component.intermediate_start + j), 0);
                            constraints.push_back(intermediate_result_constraint); // fail on oracles scalar
                        }

                        accumulated_n_constraint = accumulated_n_constraint + exponent_shift * var(component.W(1), -1) - var(component.W(1), 0);

                        constraints.push_back(accumulated_n_constraint);

                        nil::crypto3::zk::snark::plonk_gate<BlueprintFieldType, nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> gate(first_selector_index, constraints);
                        bp.add_gate(gate);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize>
                        void generate_copy_constraints(
                        const plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                       	using var = typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::var;

                        var zero(component.W(0), start_row_index, false, var::column_type::constant);
                        var one(component.W(0), start_row_index + 1, false, var::column_type::constant);

                        for (std::size_t row = start_row_index + 1; row < start_row_index + component.rows_amount; row++) {
                            bp.add_copy_constraint({{component.W(0), static_cast<int>(row), false}, instance_input.base});
                        }
                        bp.add_copy_constraint({{component.W(1), static_cast<int>(start_row_index), false}, zero});
                        bp.add_copy_constraint({{component.W(component.intermediate_start + component.intermediate_results_per_row - 1),
                                                 static_cast<int>(start_row_index), false},
                                                one});
                        // check that the recalculated n is equal to the input challenge
                        bp.add_copy_constraint(
                           {{component.W(1), static_cast<int>(start_row_index + component.rows_amount - 1), false}, instance_input.exponent}); // fail on oracles scalar
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize>
                        void generate_assignments_constants(
                            const plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15> &component,
                            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_exponentiation<BlueprintFieldType, ArithmetizationParams, ExponentSize, 15>::input_type instance_input,
                            const std::uint32_t start_row_index) {

                            std::size_t row = start_row_index;
                            assignment.constant(component.W(0), row) = 0;
                            row++;
                            assignment.constant(component.W(0), row) = 1;
                            row++;
                }
            }    // namespace components
        }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP
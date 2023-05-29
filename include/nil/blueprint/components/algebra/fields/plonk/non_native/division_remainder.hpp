//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_DIVISION_REMAINDER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_DIVISION_REMAINDER_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/range_check.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <type_traits>
#include <utility>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount, std::size_t R, bool CheckInputs>
            class division_remainder;

            /*
                For x, y < 2^{R} bits, where R < modulus_bits / 2, we divide x by y:
                x = qy + r, r < y,
                outputting q and r.
                If CheckInputs = true, this checks that x and y satisfy x, y < 2^{R}.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, bool CheckInputs>
            class division_remainder<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                                     WitnessesAmount, R, CheckInputs> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                using range_check_component_type =
                    range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>,
                                WitnessesAmount, R>;

                constexpr static const std::size_t range_check_amount = 2 + 2 * CheckInputs;

                std::array<range_check_component_type, range_check_amount> range_checks;

                constexpr static const bool needs_bonus_row = WitnessesAmount < 5;
                constexpr static const std::size_t rows_amount =
                    range_check_amount * range_check_component_type::rows_amount + 1 + needs_bonus_row;
                constexpr static const std::size_t gates_amount = 1;

                enum var_address {
                    X, Y, Q, R_, Y_MINUS_R
                };

                constexpr static const std::pair<std::size_t, std::size_t> get_var_address(
                        var_address var_ad, std::size_t start_row_index) {
                    std::size_t row = start_row_index + var_ad / WitnessesAmount,
                                column = var_ad % WitnessesAmount;
                    return std::make_pair(row, column);
                }

                var get_var_for_gate(var_address var_ad) const {
                    auto address = get_var_address(var_ad, 0);
                    return var(this->W(address.second), address.first, true);
                }

                struct input_type {
                    var x, y;
                };

                struct result_type {
                    var quotient, remainder;

                    result_type(const division_remainder &component, std::size_t start_row_index) {
                        std::pair<std::size_t, std::size_t>
                            r_address = component.get_var_address(var_address::R_, start_row_index),
                            q_address = component.get_var_address(var_address::Q, start_row_index);

                        quotient = var(component.W(q_address.second), q_address.first);
                        remainder = var(component.W(r_address.second), r_address.first);
                    }
                };

                template<typename ContainerType, std::size_t... Is>
                division_remainder(ContainerType witness, std::index_sequence<Is...>):
                    component_type(witness, {}, {}),
                    range_checks({((void) Is, range_check_component_type(witness, {}, {}))...})
                {};

                template<typename ContainerType>
                division_remainder(ContainerType witness) :
                    division_remainder(witness, {}, {}, std::make_index_sequence<range_check_amount>{})
                {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType, std::size_t... Is>
                division_remainder(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::index_sequence<Is...>):
                    component_type(witness, constant, public_input),
                    range_checks({((void) Is, range_check_component_type(witness, constant, public_input))...})
                {};


                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                division_remainder(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input):
                    division_remainder(witness, constant, public_input, std::make_index_sequence<range_check_amount>{})
                {};

                template<std::size_t... Is>
                division_remainder(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::index_sequence<Is...>) :
                            component_type(witnesses, constants, public_inputs),
                            range_checks(
                                {((void) Is, range_check_component_type(witnesses, constants, public_inputs))...})
                {};

                division_remainder(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                            division_remainder(
                                witnesses, constants, public_inputs, std::make_index_sequence<range_check_amount>{})
                {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, bool CheckInputs>
            using plonk_division_remainder =
                division_remainder<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>,
                                   WitnessesAmount, R, CheckInputs>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, bool CheckInputs,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits / 2, bool> = true>
            void generate_gates(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, CheckInputs>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R, CheckInputs>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R, CheckInputs>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;

                var x = component.get_var_for_gate(var_address::X),
                    y = component.get_var_for_gate(var_address::Y),
                    r = component.get_var_for_gate(var_address::R_),
                    q = component.get_var_for_gate(var_address::Q),
                    y_minus_r = component.get_var_for_gate(var_address::Y_MINUS_R);

                std::vector<constraint_type> constraints;
                constraint_type division_constraint = x - y * q - r;
                constraints.push_back(division_constraint);
                constraint_type y_minus_r_constraint = y - r - y_minus_r;
                constraints.push_back(y_minus_r_constraint);

                gate_type division_gate = gate_type(first_selector_index, constraints);
                bp.add_gate(division_gate);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, bool CheckInputs,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits / 2, bool> = true>
            void generate_copy_constraints(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, CheckInputs>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R, CheckInputs>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R, CheckInputs>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                std::uint32_t row = start_row_index;

                std::pair<std::size_t, std::size_t>
                    x_address = component.get_var_address(var_address::X, start_row_index),
                    y_address = component.get_var_address(var_address::Y, start_row_index);

                bp.add_copy_constraint({instance_input.x, var(component.W(x_address.second), x_address.first)});
                bp.add_copy_constraint({instance_input.y, var(component.W(y_address.second), y_address.first)});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, bool CheckInputs,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits / 2, bool> = true>
            typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount, R, CheckInputs>::result_type
            generate_circuit(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, CheckInputs>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R, CheckInputs>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                std::size_t row = start_row_index;

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R, CheckInputs>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;

                std::pair<std::size_t, std::size_t>
                    x_address = component.get_var_address(var_address::X, start_row_index),
                    y_address = component.get_var_address(var_address::Y, start_row_index),
                    r_address = component.get_var_address(var_address::R_, start_row_index),
                    q_address = component.get_var_address(var_address::Q, start_row_index),
                    y_minus_r_address = component.get_var_address(var_address::Y_MINUS_R, start_row_index);

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, start_row_index);
                row += 1 + component.needs_bonus_row;

                generate_circuit(component.range_checks[0], bp, assignment,
                                 {var(component.W(y_minus_r_address.second), y_minus_r_address.first)}, row);
                row += component.range_checks[0].rows_amount;

                generate_circuit(component.range_checks[1], bp, assignment,
                                 {var(component.W(q_address.second), q_address.first)}, row);
                row += component.range_checks[1].rows_amount;

                if (CheckInputs) {
                    generate_circuit(component.range_checks[2], bp, assignment,
                                     {var(component.W(x_address.second), x_address.first)}, row);
                    row += component.range_checks[2].rows_amount;

                    generate_circuit(component.range_checks[3], bp, assignment,
                                     {var(component.W(y_address.second), y_address.first)}, row);
                    row += component.range_checks[3].rows_amount;
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, bool CheckInputs,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits / 2, bool> = true>
            typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount, R, CheckInputs>::result_type
            generate_assignments(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, CheckInputs>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R, CheckInputs>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R, CheckInputs>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;

                value_type x = var_value(assignment, instance_input.x),
                           y = var_value(assignment, instance_input.y);
                integral_type x_integral = integral_type(x.data),
                              y_integral = integral_type(y.data);
                integral_type q_integral = y_integral != 0 ? x_integral / y_integral : 0,
                              r_integral = y_integral != 0 ? x_integral % y_integral : 0;
                value_type q = value_type(q_integral),
                           r = value_type(r_integral);

                std::pair<std::size_t, std::size_t>
                    x_address = component.get_var_address(var_address::X, start_row_index),
                    y_address = component.get_var_address(var_address::Y, start_row_index),
                    r_address = component.get_var_address(var_address::R_, start_row_index),
                    q_address = component.get_var_address(var_address::Q, start_row_index),
                    y_minus_r_address = component.get_var_address(var_address::Y_MINUS_R, start_row_index);

                assignment.witness(component.W(x_address.second), x_address.first) = x;
                assignment.witness(component.W(y_address.second), y_address.first) = y;
                assignment.witness(component.W(r_address.second), r_address.first) = r;
                assignment.witness(component.W(q_address.second), q_address.first) = q;
                assignment.witness(component.W(y_minus_r_address.second), y_minus_r_address.first) = y - r;
                row += 1 + component.needs_bonus_row;

                generate_assignments(component.range_checks[0], assignment,
                                     {var(component.W(y_minus_r_address.second), y_minus_r_address.first)}, row);
                row += component.range_checks[0].rows_amount;

                generate_assignments(component.range_checks[1], assignment,
                                     {var(component.W(q_address.second), q_address.first)}, row);
                row += component.range_checks[1].rows_amount;

                if (CheckInputs) {
                    generate_assignments(component.range_checks[2], assignment,
                                         {var(component.W(x_address.second), x_address.first)}, row);
                    row += component.range_checks[2].rows_amount;

                    generate_assignments(component.range_checks[3], assignment,
                                         {var(component.W(y_address.second), y_address.first)}, row);
                    row += component.range_checks[3].rows_amount;
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_DIVISION_REMAINDER_HPP

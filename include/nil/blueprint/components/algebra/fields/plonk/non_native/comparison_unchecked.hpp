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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_ALGEBRA_FIELDS_PLONK_NON_NATIVE_COMPARISON_UNCHECKED_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_ALGEBRA_FIELDS_PLONK_NON_NATIVE_COMPARISON_UNCHECKED_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/comparison_mode.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/range_check.hpp>

#include <type_traits>
#include <utility>

namespace nil {
    namespace blueprint {
        namespace components {
            using detail::comparison_mode;

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount, std::size_t R, comparison_mode Mode>
            class comparison_unchecked;

            /*
                Compare x and y, failing if the comparsion is not satisfied.
                x and y should fit into R bits. This isn't checked.
                Additionally, R has to satisfy: R < modulus_bits - 1.

                In the less case this is implemented by just calling the range_check component for y - x, and checking
                that y - x is not zero. Other cases are similar.

                Takes one gate less for R divisible by range_check's chunk_size -- because range_check takes
                one gate less in this case.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, comparison_mode Mode>
            class comparison_unchecked<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                             WitnessesAmount, R, Mode> :
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

                range_check_component_type range_check;

                constexpr static const bool needs_bonus_row = WitnessesAmount <= 3 &&
                                                              (Mode == comparison_mode::LESS_THAN ||
                                                               Mode == comparison_mode::GREATER_THAN);

                constexpr static const std::size_t rows_amount =
                    range_check_component_type::rows_amount + 1 + needs_bonus_row;
                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    var x, y;
                };

                struct result_type {
                    result_type(const comparison_unchecked &component, std::size_t start_row_index) {}
                };

                template <typename ContainerType>
                    comparison_unchecked(ContainerType witness):
                        component_type(witness, {}, {}),
                        range_check(witness, {}, {}) {};

                template <typename WitnessContainerType, typename ConstantContainerType,
                          typename PublicInputContainerType>
                    comparison_unchecked(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input):
                        component_type(witness, constant, public_input),
                        range_check(witness, constant, public_input) {};

                comparison_unchecked(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                            component_type(witnesses, constants, public_inputs),
                            range_check(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, comparison_mode Mode>
            using plonk_comparison_unchecked =
                comparison_unchecked<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>,
                                     WitnessesAmount, R, Mode>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, comparison_mode Mode,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1 &&
                                      Mode != comparison_mode::FLAG, bool> = true>
            void generate_gates(
                const plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                 WitnessesAmount, R, Mode>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount, R, Mode>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                      WitnessesAmount, R, Mode>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;

                typename BlueprintFieldType::value_type base_two = 2;

                std::vector<constraint_type> correctness_constraints;
                constraint_type diff_constraint = var(component.W(2), 0, true) - var(component.W(1), 0, true) +
                                                  var(component.W(0), 0, true),
                                non_zero_constraint;
                correctness_constraints.push_back(diff_constraint);
                switch (Mode) {
                    case comparison_mode::GREATER_EQUAL:
                    case comparison_mode::LESS_EQUAL:
                        break;
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::GREATER_THAN:
                        if (!component.needs_bonus_row) {
                            non_zero_constraint = var(component.W(2), 0, true) * var(component.W(3), 0, true) - 1;
                        } else {
                            non_zero_constraint = var(component.W(2), 0, true) * var(component.W(0), 1, true) - 1;
                        }
                        correctness_constraints.push_back(non_zero_constraint);
                        break;
                }

                gate_type gate = gate_type(first_selector_index, correctness_constraints);
                bp.add_gate(gate);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, comparison_mode Mode,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1 &&
                                      Mode != comparison_mode::FLAG, bool> = true>
            void generate_copy_constraints(
                const plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, Mode>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount, R, Mode>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount, R, Mode>::var;
                std::uint32_t row = start_row_index;

                row += component.rows_amount - 1 - component.needs_bonus_row;
                var x_var = var(component.W(0), row, false),
                    y_var = var(component.W(1), row, false);
                switch (Mode) {
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::LESS_EQUAL:
                        break;
                    case comparison_mode::GREATER_THAN:
                    case comparison_mode::GREATER_EQUAL:
                        std::swap(x_var, y_var);
                        break;
                }
                bp.add_copy_constraint({instance_input.x, x_var});
                bp.add_copy_constraint({instance_input.y, y_var});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, comparison_mode Mode,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1 &&
                                      Mode != comparison_mode::FLAG, bool> = true>
            typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount, R, Mode>::result_type
            generate_circuit(
                const plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, Mode>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R, Mode>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R, Mode>::var;
                generate_circuit(component.range_check, bp, assignment,
                                 {var(component.W(2), start_row_index + component.range_check.rows_amount)},
                                 start_row_index);

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                std::size_t final_first_row = start_row_index + component.rows_amount - 1 -
                                                 component.needs_bonus_row;
                assignment.enable_selector(first_selector_index, final_first_row);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessesAmount, R, Mode>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R, comparison_mode Mode,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1 &&
                                      Mode != comparison_mode::FLAG, bool> = true>
            typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount, R, Mode>::result_type
            generate_assignments(
                const plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R, Mode>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R, Mode>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_comparison_unchecked<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R, Mode>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;

                value_type x = var_value(assignment, instance_input.x),
                           y = var_value(assignment, instance_input.y);
                switch (Mode) {
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::LESS_EQUAL:
                        break;
                    case comparison_mode::GREATER_THAN:
                    case comparison_mode::GREATER_EQUAL:
                        std::swap(x, y);
                        break;
                }
                value_type diff = y - x;

                row += component.range_check.rows_amount;

                assignment.witness(component.W(0), row) = x;
                assignment.witness(component.W(1), row) = y;
                assignment.witness(component.W(2), row) = diff;
                // Note that we fill rows below the current value of row!
                generate_assignments(component.range_check, assignment,
                                     {var(component.W(2), row)},
                                     start_row_index);

                switch (Mode) {
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::GREATER_THAN:
                        if (!component.needs_bonus_row) {
                            assignment.witness(component.W(3), row) = diff != 0 ? 1 / diff : 0;
                        } else {
                            row++;
                            assignment.witness(component.W(0), row) = diff != 0 ? 1 / diff : 0;
                        }
                        break;
                    case comparison_mode::LESS_EQUAL:
                    case comparison_mode::GREATER_EQUAL:
                        break;
                }
                row++;

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_ALGEBRA_FIELDS_PLONK_NON_NATIVE_COMPARISON_UNCHECKED_HPP
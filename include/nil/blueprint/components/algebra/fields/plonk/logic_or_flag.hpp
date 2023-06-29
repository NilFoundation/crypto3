//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_LOGIC_OR_FLAG_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_LOGIC_OR_FLAG_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            /** || component
             *  Input: x, y
             *  Output: f = 0 if x=y=0, f=1 otherwise
             *
             *  Constraints:
             *      x*v_x = f_x
             *      f_x(f_x-1) = 0
             *      (v_x-x)(f_x-1) = 0
             *      y*v_y = f_y
             *      f_y(f_y-1) = 0
             *      (v_y-y)(f_y-1) = 0
             *      f_x + f_y - f_x * f_y = f
             *
             *  First convert each input to 0 or 1, then apply usual boolean || operator
             * */

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class logic_or_flag;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class logic_or_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                WitnessesAmount>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0> {

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                const std::size_t gates_amount = 1 + 1 * (WitnessesAmount == 2);
                const std::size_t rows_amount =
                    WitnessesAmount <= 4 ? 6 - WitnessesAmount : (WitnessesAmount < 7 ? 2 : 1);

                struct input_type {
                    var x;
                    var y;
                };

                struct result_type {
                    var output;

                    result_type(const logic_or_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                    WitnessesAmount> &component,
                                std::uint32_t start_row_index) {
                        output =
                            var(component.W(WitnessesAmount - 1), start_row_index + component.rows_amount - 1, false);
                    }
                };

                template<typename ContainerType>
                logic_or_flag(ContainerType witness) : component_type(witness, {}, {}) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_or_flag(WitnessContainerType witness, ConstantContainerType constant,
                              PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                logic_or_flag(std::initializer_list<typename component_type::witness_container_type::value_type>
                                  witnesses,
                              std::initializer_list<typename component_type::constant_container_type::value_type>
                                  constants,
                              std::initializer_list<typename component_type::public_input_container_type::value_type>
                                  public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            using plonk_logic_or_flag_component =
                logic_or_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                   WitnessesAmount>::result_type
                generate_assignments(
                    const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                                 WitnessesAmount>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = WitnessesAmount;

                std::array<typename BlueprintFieldType::value_type, 7> t;

                t[0] = var_value(assignment, instance_input.x);
                t[1] = var_value(assignment, instance_input.y);
                t[2] = t[0].is_zero() ? t[0] : t[0].inversed();
                t[3] = t[1].is_zero() ? t[1] : t[1].inversed();
                t[4] = t[0] * t[2];
                t[5] = t[1] * t[3];
                t[6] = t[4] + t[5] - t[4] * t[5];

                std::size_t _idx;
                for (std::size_t i = 0; i < component.rows_amount; i++) {
                    for (std::size_t j = 0; j < witness_amount; j++) {
                        _idx = i * witness_amount + j;
                        assignment.witness(component.W(j), row + i) = t[_idx % 7];
                    }
                }
                // store the output in last column, last row
                assignment.witness(component.W(witness_amount - 1), row + component.rows_amount - 1) = t[6];

                return typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            void generate_gates(
                const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                             WitnessesAmount>::input_type &instance_input,
                const std::uint32_t first_selector_index) {

                using var = typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                                   WitnessesAmount>::var;

                std::size_t offset = component.rows_amount == 3 ? -1 : 0;
                std::size_t witness_amount = WitnessesAmount;

                std::array<std::pair<std::size_t, std::size_t>, 6> wl;

                int _idx;
                for (int i = 0; i < component.rows_amount; i++) {
                    for (int j = 0; j < witness_amount; j++) {
                        _idx = i * witness_amount + j;
                        if (_idx < 6) {
                            wl[_idx] = std::make_pair(j, i + offset);
                        }
                    }
                }

                auto _x = var(component.W(wl[0].first), wl[0].second), _y = var(component.W(wl[1].first), wl[1].second),
                     _vx = var(component.W(wl[2].first), wl[2].second),
                     _vy = var(component.W(wl[3].first), wl[3].second),
                     _fx = var(component.W(wl[4].first), wl[4].second),
                     _fy = var(component.W(wl[5].first), wl[5].second),
                     _f = var(component.W(witness_amount - 1), offset + component.rows_amount - 1);

                auto constraint_1 = bp.add_constraint(_fx - _x * _vx);            // fx =x*vx
                auto constraint_2 = bp.add_constraint(_fy - _y * _vy);            // fy =y*vy

                auto constraint_3 = bp.add_constraint(_fx * (_fx - 1));           // fx(fx-1)=0
                auto constraint_4 = bp.add_constraint(_fy * (_fy - 1));           // fy(fy-1)=0

                auto constraint_5 = bp.add_constraint((_vx - _x) * (_fx - 1));    // (vx-x)(fx-1)=0
                auto constraint_6 = bp.add_constraint((_vy - _y) * (_fy - 1));    // (vy-y)(fy-1)=0

                if (witness_amount == 2) {
                    _fx = var(component.W(wl[4].first), 0), _fy = var(component.W(wl[5].first), 0),
                    _f = var(component.W(witness_amount - 1), +1);
                    auto constraint_7 = bp.add_constraint(_f - _fx - _fy + _fx * _fy);    // f = f_x + f_y - f_x*f_y
                    bp.add_gate(first_selector_index,
                                {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6});
                    bp.add_gate(first_selector_index + 1, {constraint_7});
                } else {
                    auto constraint_7 = bp.add_constraint(_f - _fx - _fy + _fx * _fy);    // f = f_x + f_y - f_x*f_y
                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4,
                                                       constraint_5, constraint_6, constraint_7});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            void generate_copy_constraints(
                const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                             WitnessesAmount>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                using var = typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                                   WitnessesAmount>::var;

                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.x});
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                   WitnessesAmount>::result_type
                generate_circuit(
                    const plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                                 WitnessesAmount>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                assignment.enable_selector(first_selector_index,
                                           start_row_index + (component.rows_amount == 3 ? 1 : 0));
                if (WitnessesAmount == 2) {
                    assignment.enable_selector(first_selector_index + 1, start_row_index + 2);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_logic_or_flag_component<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_LOGIC_OR_FLAG_HPP
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_BOOLEAN_OP_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_BOOLEAN_OP_COMPONENT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <type_traits>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                /*
                    This is a generalized boolean operation component.
                    It abstracts boolean functions with ArgNum variables, when:
                    a) ArgNum + 1 < WitnessesAmount
                    b) The function is implemented as a single constraint.
                    No checks that arguments are boolean are performed.
                */
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount, std::uint32_t ArgNum>
                class boolean_op_component;

                template<typename BlueprintFieldType, typename ArithmetizationParams,
                         std::uint32_t WitnessesAmount, std::uint32_t ArgNum>
                class boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                    ArithmetizationParams>,
                                        WitnessesAmount, ArgNum>
                                : public plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, 0, 0> {

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;
                    using value_type = typename BlueprintFieldType::value_type;

                public:
                    using var = typename component_type::var;

                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    constexpr static const std::size_t args_amount = ArgNum;

                    virtual crypto3::zk::snark::plonk_constraint<BlueprintFieldType>
                        op_constraint(const std::array<var, ArgNum + 1> &witnesses) const = 0;

                    virtual value_type result_assignment(const std::array<value_type, ArgNum> &input_values) const = 0;

                    struct input_type {
                        std::array<var, ArgNum> input;

                        input_type() = default;
                        input_type(std::initializer_list<var> input) : input(input) {};
                    };

                    struct result_type {
                        var output;

                        result_type(const boolean_op_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                            WitnessesAmount, ArgNum> &component,
                                                    const std::uint32_t start_row_index) {
                            output = var(component.W(ArgNum), start_row_index, false);
                        }
                    };

                    template<typename ContainerType>
                    boolean_op_component(ContainerType witness) : component_type(witness,
                                                                                std::array<std::uint32_t, 0>(),
                                                                                std::array<std::uint32_t, 0>()) {};

                    template<typename WitnessContainerType, typename ConstantContainerType,
                            typename PublicInputContainerType>
                    boolean_op_component(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input) :
                        component_type(witness, constant, public_input) {};

                    boolean_op_component(std::initializer_list<typename
                                                                    component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                        component_type(witnesses, constants, public_inputs) {};
                };
            }   // namespace detail

            using detail::boolean_op_component;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::uint32_t ArgNum>
            using plonk_boolean_op_component =
                boolean_op_component<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                ArithmetizationParams>,
                                     WitnessesAmount, ArgNum>;

            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t WitnessesAmount, std::uint32_t ArgNum,
                     std::enable_if_t<WitnessesAmount == ArgNum + 1, bool> = true>
            typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount, ArgNum>::result_type
                generate_assignments(
                    const plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessesAmount, ArgNum> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount, ArgNum>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                                  WitnessesAmount, ArgNum>;
                using value_type = typename BlueprintFieldType::value_type;

                std::uint32_t col_idx = 0;
                std::array<value_type, ArgNum> input_vals;
                for (; col_idx < ArgNum; col_idx++) {
                    assignment.witness(component.W(col_idx), start_row_index) =
                        input_vals[col_idx] = var_value(assignment, instance_input.input[col_idx]);
                }
                assignment.witness(component.W(col_idx), start_row_index) = component.result_assignment(input_vals);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t WitnessesAmount, std::uint32_t ArgNum,
                     std::enable_if_t<WitnessesAmount == ArgNum + 1, bool> = true>
            void generate_gates(
                const plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ArgNum>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount, ArgNum>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, ArgNum>::var;

                std::array<var, WitnessesAmount> witnesses;
                for (std::size_t col_idx = 0; col_idx < WitnessesAmount; col_idx++) {
                    witnesses[col_idx] = var(component.W(col_idx), 0);
                }
                auto constraint = bp.add_constraint(
                    component.op_constraint(witnesses));
                bp.add_gate(first_selector_index, {constraint});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t WitnessesAmount, std::uint32_t ArgNum,
                     std::enable_if_t<WitnessesAmount == ArgNum + 1, bool> = true>
            void generate_copy_constraints(
                const plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, ArgNum>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount, ArgNum>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, ArgNum>::var;

                std::size_t row = start_row_index;

                for (std::size_t col_idx = 0; col_idx < ArgNum; col_idx++) {
                    bp.add_copy_constraint({instance_input.input[col_idx],
                                            var(component.W(col_idx), (std::int32_t)(row), false)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams,
                     std::uint32_t WitnessesAmount, std::uint32_t ArgNum,
                     std::enable_if_t<WitnessesAmount == ArgNum + 1, bool> = true>
            typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount, ArgNum>::result_type
                generate_circuit(
                    const plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessesAmount, ArgNum> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount, ArgNum>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                using component_type = plonk_boolean_op_component<BlueprintFieldType, ArithmetizationParams,
                                                                  WitnessesAmount, ArgNum>;

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                assignment.enable_selector(first_selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }   // namespace components
    }       // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_BOOLEAN_OP_COMPONENT_HPP

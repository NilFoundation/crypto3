//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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
// @file Declaration of interfaces for PLONK field element division component.
// If divider is zero, component's result is zero either. 
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_DIVISION_OR_ZERO_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_DIVISION_OR_ZERO_HPP

#include <cmath>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x, y \in Fp
            // Output: z = x / y, if y != 0, else 0 z \in F_p
            template<typename ArithmetizationType, typename FieldType, std::uint32_t WitnessesAmount>
            class division_or_zero;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class division_or_zero<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, 5>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 5, 0, 0> {

                constexpr static const std::int32_t WitnessAmount = 5;
            
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount, 0, 0>;

            public:

                const std::size_t gates_amount = 1;

                using var = typename component_type::var;

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const division_or_zero &component, std::uint32_t start_row_index) {
                        output = var(component.W(2), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const division_or_zero &component, std::size_t start_row_index) {
                        output = var(component.W(2), start_row_index, false, var::column_type::witness);
                    }
                };

                template <typename ContainerType>
                division_or_zero(ContainerType witness):
                    component_type(witness, {}, {}){};

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                division_or_zero(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input):
                    component_type(witness, constant, public_input){};

                division_or_zero(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs):
                    component_type(witnesses, constants, public_inputs){};
            };

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams,
                     std::int32_t WitnessAmount>
            using plonk_division_or_zero =
                division_or_zero<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, WitnessAmount>;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::result_type
                generate_assignments(
                    const plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                assignment.witness(component.W(0), j) = var_value(assignment, instance_input.x);
                assignment.witness(component.W(1), j) = var_value(assignment, instance_input.y);
                if (var_value(assignment, instance_input.y) != 0) {
                    assignment.witness(component.W(2), j) = var_value(assignment, instance_input.x) /
                        var_value(assignment, instance_input.y);
                } else {
                    assignment.witness(component.W(2), j) = 0;
                }
                assignment.witness(component.W(3), j) = (var_value(assignment, instance_input.y) == 0) ?
                    0 : var_value(assignment, instance_input.y).inversed();
                assignment.witness(component.W(4), j) = var_value(assignment, instance_input.y) * assignment.witness(component.W(3), j);

                return typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_gates(
                const plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::input_type &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::var;

                auto constraint_1 = bp.add_constraint(var(component.W(1), 0) * var(component.W(3), 0) - var(component.W(4), 0));
                auto constraint_2 = bp.add_constraint(var(component.W(4), 0) * (var(component.W(4), 0) - 1));
                auto constraint_3 = bp.add_constraint((var(component.W(3), 0) - var(component.W(1), 0)) * (var(component.W(4), 0) - 1));
                auto constraint_4 = bp.add_constraint(var(component.W(0), 0) * var(component.W(3), 0) - var(component.W(2), 0));

                bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                var component_y = var(component.W(1), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
                bp.add_copy_constraint({component_y, instance_input.y});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::result_type
                generate_circuit(
                    const plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::input_type &instance_input,
                    const std::size_t start_row_index){

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;

                if (selector_iterator == assignment.selectors_end()){
                    first_selector_index = assignment.allocate_selector(component,
                        component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_division_or_zero<BlueprintFieldType, ArithmetizationParams, 5>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_DIVISION_OR_ZERO_HPP

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
// @file Declaration of interfaces for PLONK field element multiplication by constant component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_MULTIPLICATION_BY_CONSTANT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_MULTIPLICATION_BY_CONSTANT_HPP

#include <cmath>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x, c \in F_p, c is fixed public parameter
            // Output: z = c * y, z \in F_p
            template<typename ArithmetizationType, typename FieldType>
            class mul_by_constant;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            class mul_by_constant<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

            public:
                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return mul_by_constant::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static constexpr const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(2)),
                        true
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                value_type constant;

                struct input_type {
                    var x = var(0, 0, false);
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const mul_by_constant &component, std::uint32_t start_row_index) {
                        output = var(component.W(1), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const mul_by_constant &component, std::size_t start_row_index) {
                        output = var(component.W(1), start_row_index, false, var::column_type::witness);
                    }
                };

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                mul_by_constant(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, value_type constant_):
                    component_type(witness, constant, public_input, get_manifest()),
                    constant(constant_) {};

                mul_by_constant(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs,
                        value_type constant_):
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    constant(constant_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_mul_by_constant =
                mul_by_constant<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                assignment.witness(component.W(0), j) = var_value(assignment, instance_input.x);
                assignment.witness(component.W(1), j) = component.constant *
                    var_value(assignment, instance_input.x);

                return typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_gates(
                const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::var;

                auto constraint_1 = bp.add_constraint(
                    var(component.W(0), 0) * var(0, 0, true, var::column_type::constant) - var(component.W(1), 0));

                bp.add_gate(first_selector_index, {constraint_1});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

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
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = component.constant;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_MULTIPLICATION_BY_CONSTANT_HPP

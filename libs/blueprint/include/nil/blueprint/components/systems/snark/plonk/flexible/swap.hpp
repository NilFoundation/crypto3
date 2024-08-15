//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_swap_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_swap_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Input: array of triples <<b1, c1, d1>
            // Output: array of pairs where if b_i == 0 => <c_i, d_i>,  else <d_i, c_i>
            // b1, c1, d1, output1_0, output1_1, b2, c2, d2, output2_0, output2_1, ...
            template<typename ArithmetizationType, typename FieldType>
            class flexible_swap;

            template<typename BlueprintFieldType>
            class flexible_swap<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return flexible_swap::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(5)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                    std::size_t witness_amount
                ) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());

                struct input_type {
	                std::array<var, 3> inp; // the array of pairs of elements

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.push_back(inp[0]);
                        result.push_back(inp[1]);
                        result.push_back(inp[2]);
                        return result;
                    }
                };

                struct result_type {
		            std::array<var, 2> output; // the array with possibly swapped elements

                    result_type(const flexible_swap &component, std::size_t start_row_index) {
                        output[0] = var(component.W(3), start_row_index, false);
                        output[1] = var(component.W(4), start_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.push_back(output[0]);
                        result.push_back(output[1]);
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit flexible_swap(ContainerType witness, std::size_t _n) :
                    component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                flexible_swap(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()){};

                flexible_swap(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest())
                    {};
            };

            template<typename BlueprintFieldType>
            using plonk_flexible_swap =
                flexible_swap<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_flexible_swap<BlueprintFieldType>::result_type generate_assignments(
                const plonk_flexible_swap<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_swap<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_flexible_swap<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                auto b = var_value(assignment, instance_input.inp[0]);
                auto c = var_value(assignment, instance_input.inp[1]);
                auto d = var_value(assignment, instance_input.inp[2]);

                assignment.witness(component.W(0), start_row_index) = b;
                assignment.witness(component.W(1), start_row_index) = c;
                assignment.witness(component.W(2), start_row_index) = d;
                assignment.witness(component.W(3), start_row_index) = b == 0? c: d;
                assignment.witness(component.W(4), start_row_index) = b == 0? d: c;
                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            typename plonk_flexible_swap<BlueprintFieldType>::result_type generate_empty_assignments(
                const plonk_flexible_swap<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_swap<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_flexible_swap<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                auto b = var_value(assignment, instance_input.inp[0]);
                auto c = var_value(assignment, instance_input.inp[1]);
                auto d = var_value(assignment, instance_input.inp[2]);

                assignment.witness(component.W(0), start_row_index) = b;
                assignment.witness(component.W(1), start_row_index) = c;
                assignment.witness(component.W(2), start_row_index) = d;
                assignment.witness(component.W(3), start_row_index) = b == 0? c: d;
                assignment.witness(component.W(4), start_row_index) = b == 0? d: c;
                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_flexible_swap<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_swap<BlueprintFieldType>::input_type
                    &instance_input
            ) {
                using component_type = plonk_flexible_swap<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::vector<constraint_type> constraints;

                var input_b_var = var(component.W(0), 0, true),
                    input_c_var = var(component.W(1), 0, true),
                    input_d_var = var(component.W(2), 0, true),
                    output0_var = var(component.W(3), 0, true),
                    output1_var = var(component.W(4), 0, true);

                constraints.emplace_back(input_b_var * (input_b_var - 1));
                constraints.emplace_back(output0_var - ((1-input_b_var) * input_c_var + input_b_var * input_d_var));
                constraints.emplace_back(output1_var - ((1-input_b_var) * input_d_var + input_b_var * input_c_var));

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_flexible_swap<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_swap<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_flexible_swap<BlueprintFieldType>;
                using var = typename component_type::var;

                bp.add_copy_constraint(
                    {std::get<0>(instance_input.inp), var(component.W(0), start_row_index, false)});
                bp.add_copy_constraint(
                    {std::get<1>(instance_input.inp), var(component.W(1), start_row_index, false)});
                bp.add_copy_constraint(
                    {std::get<2>(instance_input.inp), var(component.W(2), start_row_index, false)});
            }

            template<typename BlueprintFieldType>
            typename plonk_flexible_swap<BlueprintFieldType>::result_type generate_circuit(
                const plonk_flexible_swap<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_swap<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                using component_type = plonk_flexible_swap<BlueprintFieldType>;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(
                    selector_index, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_swap_HPP
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for FRI verification linear interpolation component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_LIN_INTER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_LIN_INTER_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // linear interpolation with points (s,y0), (-s,y1) at point alpha
            // Input: s, y0, y1, alpha
            // Output: y = y0 + (y1 - y0)*(s - alpha)/(2s)
            // DOES NOT CHECK THAT s != 0
            template<typename ArithmetizationType, typename BlueprintFieldType>
            class fri_lin_inter;

            template<typename BlueprintFieldType>
            class fri_lin_inter<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fri_lin_inter::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(5)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                const std::string component_name = "fri linear interpolation component";

                struct input_type {
                    var s, y0, y1, alpha;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {s, y0, y1, alpha};
                    }
                };

                struct result_type {
		            var output;

                    result_type(const fri_lin_inter &component, std::uint32_t start_row_index) {
                        output = var(component.W(4), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fri_lin_inter(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fri_lin_inter(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                fri_lin_inter(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType>
            using plonk_fri_lin_inter =
                fri_lin_inter<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_fri_lin_inter<BlueprintFieldType>::result_type generate_assignments(
                const plonk_fri_lin_inter<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fri_lin_inter<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;
                value_type s = var_value(assignment, instance_input.s),
                           y0 = var_value(assignment, instance_input.y0),
                           y1 = var_value(assignment, instance_input.y1),
                           alpha = var_value(assignment, instance_input.alpha);

                assignment.witness(component.W(0), start_row_index) = y0;
                assignment.witness(component.W(1), start_row_index) = y1;
                assignment.witness(component.W(2), start_row_index) = s;
                assignment.witness(component.W(3), start_row_index) = alpha;
                assignment.witness(component.W(4), start_row_index) =
                    y0 + (y1 - y0) * (s - alpha) / (value_type(2) * s);

                return typename plonk_fri_lin_inter<BlueprintFieldType>::result_type(
                    component, start_row_index);
	    }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_fri_lin_inter<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fri_lin_inter<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_fri_lin_inter<BlueprintFieldType>::var;

                auto interpolation_constraint =
                    2 * var(component.W(2), 0, true) * (var(component.W(4), 0, true) - var(component.W(0), 0, true)) -
                    (var(component.W(1), 0, true) - var(component.W(0), 0, true)) *
                    (var(component.W(2), 0, true) - var(component.W(3), 0, true));

                return bp.add_gate({interpolation_constraint});
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_fri_lin_inter<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fri_lin_inter<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fri_lin_inter<BlueprintFieldType>::var;

                bp.add_copy_constraint({var(component.W(0), start_row_index, false), instance_input.y0});
                bp.add_copy_constraint({var(component.W(1), start_row_index, false), instance_input.y1});
                bp.add_copy_constraint({var(component.W(2), start_row_index, false), instance_input.s});
                bp.add_copy_constraint({var(component.W(3), start_row_index, false), instance_input.alpha});
            }

            template<typename BlueprintFieldType>
            typename plonk_fri_lin_inter<BlueprintFieldType>::result_type generate_circuit(
                const plonk_fri_lin_inter<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_fri_lin_inter<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fri_lin_inter<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_LIN_INTER_HPP

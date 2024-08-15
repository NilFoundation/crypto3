//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tablain <d.tabalin@nil.foundation>
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Generic mocked component interface class.
            // Designed to make it easy to conjure small mocked components out of thin air.
            template<typename ArithmetizationType, typename InputType, typename ResultType>
            class mocked_component_base;

            template<typename BlueprintFieldType, typename InputType, typename ResultType>
            class mocked_component_base<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                InputType, ResultType>
                    : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using value_type = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 0;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<nil::blueprint::manifest_param>(
                            new nil::blueprint::manifest_single_value_param(ResultType::result_size)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return 1;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                constexpr static const std::size_t gates_amount = 1;

                typedef InputType input_type;
                typedef ResultType result_type;

                virtual std::array<value_type, ResultType::result_size> result_values_calculator(
                    const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const input_type &instance_input) const = 0;

                virtual result_type result_builder(const std::size_t start_row_index) const = 0;

                void assigner(
                    const std::array<value_type, ResultType::result_size> &result_values,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const std::size_t start_row_index) const {

                    for (std::size_t i = 0; i < ResultType::result_size; i++) {
                        assignment.witness(this->W(i), start_row_index) = result_values[i];
                    }
                }

                template<typename ContainerType>
                explicit mocked_component_base(ContainerType witness) :
                    component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                mocked_component_base(WitnessContainerType witness, ConstantContainerType constant,
                              PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                mocked_component_base(std::initializer_list<typename component_type::witness_container_type::value_type>
                                  witnesses,
                              std::initializer_list<typename component_type::constant_container_type::value_type>
                                  constants,
                              std::initializer_list<typename component_type::public_input_container_type::value_type>
                                  public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType,
                     typename InputType, typename ResultType>
            using plonk_mocked_component_base =
                mocked_component_base<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                      InputType, ResultType>;

            template<typename BlueprintFieldType,
                     typename InputType, typename ResultType>
            typename plonk_mocked_component_base<BlueprintFieldType,
                                                 InputType, ResultType>::result_type
                generate_assignments(
                    const plonk_mocked_component_base<BlueprintFieldType,
                                                      InputType, ResultType>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_mocked_component_base<BlueprintFieldType,
                                                               InputType, ResultType>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                auto result = component.result_values_calculator(assignment, instance_input);
                component.assigner(result, assignment, start_row_index);

                return component.result_builder(start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename InputType, typename ResultType>
            typename plonk_mocked_component_base<BlueprintFieldType, InputType, ResultType>::result_type
                generate_circuit(
                    const plonk_mocked_component_base<BlueprintFieldType, InputType, ResultType>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_mocked_component_base<BlueprintFieldType, InputType, ResultType>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                return component.result_builder(start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

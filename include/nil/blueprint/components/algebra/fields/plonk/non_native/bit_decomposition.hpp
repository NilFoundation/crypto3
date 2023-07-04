//---------------------------------------------------------------------------//
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_DECOMPOSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_DECOMPOSITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/detail/get_component_id.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/bit_builder_component.hpp>

#include <type_traits>
#include <utility>
#include <sstream>
#include <string>

using nil::blueprint::components::detail::bit_builder_component;
using nil::blueprint::components::detail::bit_composition_mode;

namespace nil {
    namespace blueprint {
        namespace components {
            /*
                Decomposes a single field element into bits_amount bits.
                Output bits can be ordered LSB-first or MSB-first, depending on the value of mode parameter.

                A schematic representation of this component can be found in bit_builder_component.hpp.
            */
            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class bit_decomposition;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                            WitnessesAmount>
                                 : public
                                   bit_builder_component<crypto3::zk::snark::plonk_constraint_system<
                                                         BlueprintFieldType, ArithmetizationParams>,
                                                         WitnessesAmount> {

                using component_type =
                    bit_builder_component<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        WitnessesAmount>;

            public:
                using var = typename component_type::var;

                const bit_composition_mode mode;

                struct input_type {
                    var input;
                };

                struct result_type {
                    std::vector<var> output;
                    result_type(const bit_decomposition &component, std::uint32_t start_row_index) {
                        output.resize(component.bits_amount);
                        auto padded_bit_index = [&component](std::size_t i) {
                            return component.padding_bits_amount() +
                                    (component.mode == bit_composition_mode::MSB ?
                                        i
                                        : component.bits_amount - i - 1);
                        };

                        for (std::size_t i = 0; i < component.bits_amount; i++) {
                            auto pos = component.bit_position(start_row_index, padded_bit_index(i));
                            output[i] = var(component.W(pos.second), pos.first, false);
                        }
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessesAmount << "_" << mode << "_" << this->bits_amount;
                    return ss.str();
                }

                template<typename ContainerType>
                bit_decomposition(ContainerType witness, std::uint32_t bits_amount,
                                  bit_composition_mode mode_) :
                                        component_type(witness, bits_amount, true),
                                        mode(mode_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_decomposition(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input, std::uint32_t bits_amount,
                                  bit_composition_mode mode_) :
                    component_type(witness, constant, public_input, bits_amount, true),
                    mode(mode_) {};

                bit_decomposition(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::uint32_t bits_amount, bit_composition_mode mode_) :
                    component_type(witnesses, constants, public_inputs, bits_amount, true),
                    mode(mode_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            using plonk_bit_decomposition = bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::result_type
                generate_assignments(
                    const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams,
                                                           WitnessesAmount>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                typename BlueprintFieldType::integral_type input_data =
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.input).data);

                std::vector<bool> input_bits(component.bits_amount);
                {
                    nil::marshalling::status_type status;
                    std::array<bool, BlueprintFieldType::modulus_bits> bytes_all =
                        nil::marshalling::pack<nil::marshalling::option::big_endian>(
                            var_value(assignment, instance_input.input), status);
                    std::copy(bytes_all.end() - component.bits_amount, bytes_all.end(), input_bits.begin());
                    assert(status == nil::marshalling::status_type::success);
                }
                // calling bit_builder_component's generate_assignments
                generate_assignments<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>(
                    component, assignment, input_bits, start_row_index);

                return typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::result_type(
                            component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            void generate_copy_constraints(
                const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams,
                                                             WitnessesAmount>::var;

                std::size_t row = start_row_index;

                var zero(0, row, false, var::column_type::constant);
                std::size_t padding = 0;
                for (; padding < component.padding_bits_amount(); padding++) {
                    auto bit_pos = component.bit_position(row, padding);
                    bp.add_copy_constraint({zero,
                                            var(component.W(bit_pos.second), bit_pos.first, false)});
                }

                for (std::size_t i = 0; i < component.sum_bits_amount() - 1; i += 2) {
                    auto sum_bit_pos_1 = component.sum_bit_position(row, i);
                    auto sum_bit_pos_2 = component.sum_bit_position(row, i + 1);
                    bp.add_copy_constraint(
                        {var(component.W(sum_bit_pos_1.second), sum_bit_pos_1.first, false),
                         var(component.W(sum_bit_pos_2.second), sum_bit_pos_2.first, false)});
                }

                auto sum_pos = component.sum_bit_position(row, component.sum_bits_amount() - 1);
                bp.add_copy_constraint({instance_input.input,
                                        var(component.W(sum_pos.second), sum_pos.first, false)});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>::result_type
                generate_circuit(
                    const plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams,
                                                           WitnessesAmount>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                // calling bit_builder_component's generate_circuit
                generate_circuit<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>(
                                    component, bp, assignment, start_row_index);
                // copy constraints are specific to this component
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bit_decomposition<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::result_type(
                            component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
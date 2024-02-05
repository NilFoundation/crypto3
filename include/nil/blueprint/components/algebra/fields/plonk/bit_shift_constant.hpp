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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_SHIFT_CONSTANT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_SHIFT_CONSTANT_HPP

#include <cstddef>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/bit_builder_component.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>

#include <algorithm>
#include <utility>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {

            enum bit_shift_mode {
                LEFT,
                RIGHT,
            };

            /*
                Shits an element < 2^{bits_amount} by a constant amount of bits.
                Input has to fit into [bits_amount < BlueprintFieldType::modulus_bits - 1] bits (this is checked).
                This is implemented as decomposition + composition.
                Left shift is done modulo 2^{bits_amount}.
            */
            template<typename ArithmetizationType>
            class bit_shift_constant;


            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bit_shift_constant<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                                 : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t bits_amount,
                                                 std::size_t shift, bit_shift_mode mode) {
                    return decomposition_component_type::get_rows_amount(witness_amount, 0, bits_amount) +
                           composition_component_type::get_rows_amount(witness_amount, 0,
                                calculate_composition_bits_amount(bits_amount, shift, mode), false);
                }
            public:
                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using decomposition_component_type =
                    bit_decomposition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                  ArithmetizationParams>>;

                using composition_component_type =
                    bit_composition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                ArithmetizationParams>>;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 0;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t bits_amount,
                                                       std::size_t shift,
                                                       bit_shift_mode mode) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(decomposition_component_type::get_gate_manifest(
                                            witness_amount, lookup_column_amount, bits_amount))
                        .merge_with(composition_component_type::get_gate_manifest(
                                            witness_amount, lookup_column_amount,
                                            calculate_composition_bits_amount(bits_amount, shift, mode), false));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        decomposition_component_type::get_manifest().merge_with(
                            composition_component_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t bits_amount,
                                                             std::size_t shift, bit_shift_mode mode) {
                    return rows_amount_internal(witness_amount, bits_amount, shift, mode);
                }

                constexpr static const std::size_t rows(const decomposition_component_type& decomposition_subcomponent,
                                                        const composition_component_type& composition_subcomponent) {
                    return decomposition_subcomponent.rows_amount + composition_subcomponent.rows_amount;
                }

                constexpr static const std::uint32_t calculate_composition_bits_amount(std::uint32_t bits_amount,
                                                                                       std::uint32_t shift,
                                                                                       bit_shift_mode mode) {
                    return mode == bit_shift_mode::RIGHT ? bits_amount - shift
                                                         : bits_amount;
                }


                decomposition_component_type decomposition_subcomponent;
                composition_component_type composition_subcomponent;

                const std::size_t bits_amount;
                const std::uint32_t shift;
                const bit_shift_mode mode;

                // Technically, this component uses two gates.
                // But both of them are inside subcomponents.
                static constexpr const std::size_t gates_amount = 0;
                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), bits_amount, shift, mode);

                struct input_type {
                    var input;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {input};
                    }
                };

                struct result_type {
                    var output;

                    result_type(const bit_shift_constant &component, std::uint32_t start_row_index) {
                        std::uint32_t row = start_row_index;
                        row += component.decomposition_subcomponent.rows_amount;
                        output = typename composition_component_type::result_type(
                                    component.composition_subcomponent, row).output;
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit bit_shift_constant(ContainerType witness, std::uint32_t bits_amount_, std::uint32_t shift_,
                                            bit_shift_mode mode_) :
                    component_type(witness, {}, {}, get_manifest()),
                    decomposition_subcomponent(witness, bits_amount_, bit_composition_mode::MSB),
                    composition_subcomponent(witness,
                                             calculate_composition_bits_amount(bits_amount_, shift_, mode_),
                                             false, bit_composition_mode::MSB),
                    bits_amount(bits_amount_),
                    shift(shift_),
                    mode(mode_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_shift_constant(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input, std::uint32_t bits_amount_,
                                   std::uint32_t shift_, bit_shift_mode mode_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    decomposition_subcomponent(witness, constant, public_input,
                                               bits_amount_, bit_composition_mode::MSB),
                    composition_subcomponent(witness, constant, public_input,
                                             calculate_composition_bits_amount(bits_amount_, shift_, mode_),
                                             false, bit_composition_mode::MSB),
                    bits_amount(bits_amount_),
                    shift(shift_),
                    mode(mode_) {};

                bit_shift_constant(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::uint32_t bits_amount_, std::uint32_t shift_, bit_shift_mode mode_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        decomposition_subcomponent(witnesses, constants, public_inputs,
                                                   bits_amount_, bit_composition_mode::MSB),
                        composition_subcomponent(witnesses, constants, public_inputs,
                                                 calculate_composition_bits_amount(bits_amount_, shift_, mode_),
                                                 false, bit_composition_mode::MSB),
                        bits_amount(bits_amount_),
                        shift(shift_),
                        mode(mode_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_bit_shift_constant = bit_shift_constant<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {
                std::uint32_t row = start_row_index;

                using var = typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::var;
                using decomposition_component_type =
                    typename plonk_bit_shift_constant<BlueprintFieldType,
                                                      ArithmetizationParams>::decomposition_component_type;
                using composition_component_type =
                    typename plonk_bit_shift_constant<BlueprintFieldType,
                                                      ArithmetizationParams>::composition_component_type;

                typename decomposition_component_type::result_type decomposition =
                    generate_assignments(component.decomposition_subcomponent, assignment,
                                         {instance_input.input}, row);
                row += component.decomposition_subcomponent.rows_amount;

                typename composition_component_type::input_type composition_input;
                composition_input.bits.resize(component.composition_subcomponent.bits_amount);
                if (component.mode == bit_shift_mode::LEFT) {
                    var zero(0, start_row_index, false, var::column_type::constant);
                    std::fill(composition_input.bits.begin(), composition_input.bits.end(), zero);

                    std::move(decomposition.output.begin() + component.shift, decomposition.output.end(),
                              composition_input.bits.begin());
                } else if (component.mode == bit_shift_mode::RIGHT) {
                    std::move(decomposition.output.begin(), decomposition.output.end() - component.shift,
                              composition_input.bits.begin());
                }
                generate_assignments(component.composition_subcomponent, assignment, composition_input, row);
                row += component.composition_subcomponent.rows_amount;

                assert(row == start_row_index + component.rows_amount);
                return typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::result_type(
                                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {
                std::uint32_t row = start_row_index;

                using var = typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::var;
                using decomposition_component_type =
                    typename plonk_bit_shift_constant<BlueprintFieldType,
                                                      ArithmetizationParams>::decomposition_component_type;
                using composition_component_type =
                    typename plonk_bit_shift_constant<BlueprintFieldType,
                                                      ArithmetizationParams>::composition_component_type;

                typename decomposition_component_type::result_type decomposition =
                    generate_circuit(component.decomposition_subcomponent, bp, assignment, {instance_input.input},
                                     row);
                row += component.decomposition_subcomponent.rows_amount;

                typename composition_component_type::input_type composition_input;
                composition_input.bits.resize(component.composition_subcomponent.bits_amount);
                if (component.mode == bit_shift_mode::LEFT) {
                    // We do not need to set this constant, as it is set by the decomposition component
                    var zero(0, start_row_index, false, var::column_type::constant);
                    std::fill(composition_input.bits.begin(), composition_input.bits.end(), zero);

                    std::move(decomposition.output.begin() + component.shift, decomposition.output.end(),
                              composition_input.bits.begin());
                } else if (component.mode == bit_shift_mode::RIGHT) {
                    std::move(decomposition.output.begin(), decomposition.output.end() - component.shift,
                              composition_input.bits.begin());
                }
                generate_circuit(component.composition_subcomponent, bp, assignment, composition_input, row);
                row += component.composition_subcomponent.rows_amount;

                assert(row == start_row_index + component.rows_amount);
                return typename plonk_bit_shift_constant<BlueprintFieldType, ArithmetizationParams>::result_type(
                                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif   // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_SHIFT_CONSTANT_HPP

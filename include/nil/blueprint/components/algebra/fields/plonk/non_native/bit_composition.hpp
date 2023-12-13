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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_COMPOSITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_COMPOSITION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/bit_builder_component.hpp>

#include <utility>
#include <sstream>
#include <string>

using nil::blueprint::components::detail::bit_builder_component;
using nil::blueprint::components::bit_composition_mode;

namespace nil {
    namespace blueprint {
        namespace components {

            /*
                Makes a single field element from bits_amount bits.
                If CheckInput is true, performs a check that input values are actually in {0, 1}.
                Otherwise, assumes that input values are already in {0, 1}.
                Only the case of bits_amount < BlueprintFieldType::modulus_bits is supported.
                Bits can be passed LSB-first or MSB-first, depending on the value of Mode parameter.

                A schematic representation of this component can be found in bit_builder_component.hpp.
            */
            template<typename ArithmetizationType>
            class bit_composition;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bit_composition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                                 : public
                                   bit_builder_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                            BlueprintFieldType,
                                                                                            ArithmetizationParams>> {

                void check_params(std::size_t bits_amount, bit_composition_mode mode) const {
                    BLUEPRINT_RELEASE_ASSERT(bits_amount > 0 && bits_amount < BlueprintFieldType::modulus_bits);
                    BLUEPRINT_RELEASE_ASSERT(mode == bit_composition_mode::LSB || mode == bit_composition_mode::MSB);
                }
            public:
                using component_type =
                    bit_builder_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

                using var = typename component_type::var;
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
                                                       bool check_input, bit_composition_mode mode = bit_composition_mode::MSB) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(component_type::get_gate_manifest(witness_amount, lookup_column_amount,
                                                                             bits_amount, check_input));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    return component_type::get_manifest();
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                 std::size_t lookup_column_amount,
                                                                 std::size_t bits_amount, bool check_input, bit_composition_mode mode = bit_composition_mode::MSB) {
                    return component_type::get_rows_amount(witness_amount, lookup_column_amount,
                                                           bits_amount, check_input);
                }

                const bit_composition_mode mode;

                struct input_type {
                    std::vector<var> bits;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        for (auto& it : bits) {
                            res.push_back(it);
                        }
                        return res;
                    }
                };

                struct result_type {
                    var output;
                    result_type(const bit_composition &component, std::uint32_t start_row_index) {
                        auto pos = component.sum_bit_position(start_row_index, component.sum_bits_amount() - 1);
                        output = var(component.W(pos.second), pos.first, false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit bit_composition(ContainerType witness, std::uint32_t bits_amount, bool check_input,
                                         bit_composition_mode mode_) :
                    component_type(witness, {}, {}, get_manifest(), bits_amount, check_input), mode(mode_) {

                    check_params(bits_amount, mode);
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                bit_composition(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input,
                                std::uint32_t bits_amount, bool check_input, bit_composition_mode mode_) :
                    component_type(witness, constant, public_input, get_manifest(), bits_amount, check_input),
                    mode(mode_) {

                    check_params(bits_amount, mode);
                };

                bit_composition(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::uint32_t bits_amount, bool check_input, bit_composition_mode mode_) :
                    component_type(witnesses, constants, public_inputs, get_manifest(), bits_amount, check_input),
                    mode(mode_) {

                    check_params(bits_amount, mode);
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_bit_composition = bit_composition<crypto3::zk::snark::plonk_constraint_system<
                        BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                std::vector<bool> input_bits(component.bits_amount);

                auto bit_index = [&component](std::size_t i) {
                    return component.mode == bit_composition_mode::MSB ? i : component.bits_amount - i - 1;
                };

                for (std::uint32_t i = 0; i < component.bits_amount; ++i) {
                    input_bits[i] = var_value(assignment, instance_input.bits[bit_index(i)]) != 0 ? true : false;
                }
                // calling bit_builder_component's generate_assignments
                generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                    component, assignment, input_bits, start_row_index);

                return typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::result_type(
                                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                    const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                using var = typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;

                auto bit_index = [&component](std::size_t i) {
                    return component.mode == bit_composition_mode::MSB ? i : component.bits_amount - i - 1;
                };

                var zero(0, row, false, var::column_type::constant);
                std::size_t padding = 0;
                for (; padding < component.padding_bits_amount(); padding++) {
                    auto bit_pos = component.bit_position(row, padding);
                    bp.add_copy_constraint({zero,
                                            var(component.W(bit_pos.second), bit_pos.first, false)});
                }

                for (std::size_t i = 0; i < component.bits_amount; i++) {
                    auto bit_pos = component.bit_position(row, padding + i);
                    bp.add_copy_constraint({instance_input.bits[bit_index(i)],
                                            var(component.W(bit_pos.second), bit_pos.first, false)});
                }

                for (std::size_t i = 0; i < component.sum_bits_amount() - 1; i += 2) {
                    auto sum_bit_pos_1 = component.sum_bit_position(row, i);
                    auto sum_bit_pos_2 = component.sum_bit_position(row, i + 1);
                    bp.add_copy_constraint(
                        {var(component.W(sum_bit_pos_1.second), sum_bit_pos_1.first, false),
                         var(component.W(sum_bit_pos_2.second), sum_bit_pos_2.first, false)});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                // calling bit_builder_component's generate_circuit
                generate_circuit(component, bp, assignment, start_row_index);
                // copy constraints are specific to this component
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_bit_composition<BlueprintFieldType, ArithmetizationParams>::result_type(
                                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_COMPOSITION_HPP
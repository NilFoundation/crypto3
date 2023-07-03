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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <utility>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                enum bit_composition_mode {
                    LSB,
                    MSB,
                };
                /*
                    This is a component base, which is used for both bit_decomposition and
                    bit_builder_component components, as they are similar.

                    Only the case of bits_amount < BlueprintFieldType::modulus_bits is supported.

                    The composition part does not perfom checks that the inputs are actually bits,
                    unless the check is specifically enabled.
                    Bits should be passed here MSB-first; for LSB first, the derived component
                    should reverse the order of the bits.

                    A schematic representation of the component gate. 'o' signifies an input bit.
                    'x' signifies one of the sum bits.
                    '0' signifies padding with zeros.
                    Input bits are packed MSB first.

                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |x|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | -- The first 'x' is the previous sum.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |    The second 'x' is constrained to be equal to the
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    (weighted) sum of 'o' bits and the first 'x'.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    The first bit in the component is always padded '0' for check_bits = true, and input/padding bit
                    for check_bits = false.

                    This requires padding up to nearest value of
                    k * (3 * WitnessesAmount - 2) for check_bits = true,
                    3 * WitnessesAmount - 1 + k * (3 * WitnessesAmount - 2) for check_bits = false.

                    An example for bits_amount = 80 (90 cells: 3 sum bits, 80 input bits, 7 padding bits):
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |0|0|0|0|0|0|0|o|o|o|o|o|o|o|o| ] -- Note that here there is no difference between different
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    valuese of check_bits.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |x|o|o|o|o|o|o|o|o|o|o|o|o|o|o| ] -- The top left 'x' needs to be constrained to be equal to
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |    the bottom right 'x' in the previous constraint block.
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|o| |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
                    |o|o|o|o|o|o|o|o|o|o|o|o|o|o|x| ]
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                */
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
                class bit_builder_component;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                class bit_builder_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                                WitnessesAmount>
                                    : public plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                             WitnessesAmount, 1, 0> {

                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0>;

                    std::size_t rows(std::size_t bits_amount, bool check_bits) const {
                        std::size_t total_bits = bits_amount + sum_bits_amount_internal(bits_amount, check_bits) +
                                                               padding_bits_amount_internal(bits_amount, check_bits);
                        return total_bits / WitnessesAmount;
                    }

                    /*
                        Returns bit position inside the packing, if the packing were done by filling each row in order,
                        without skipping any cells.
                    */
                    std::pair<std::size_t, std::size_t> straight_bit_position(
                            std::size_t start_row_index, std::size_t bit_num) const{

                        std::size_t row = start_row_index + bit_num / WitnessesAmount;
                        std::size_t col = bit_num % WitnessesAmount;

                        return std::make_pair(row, col);
                    };

                    std::size_t padding_bits_amount_internal(std::size_t bits_amount_, bool check_bits_) const {
                        if (check_bits_) {
                            // in this case, first bit always has to be padded '0'
                            if (bits_amount_ > bits_per_gate) {
                                return 1 + (bits_per_gate - bits_amount_ % bits_per_gate) % bits_per_gate;
                            } else {
                                return bits_per_gate + 1 - bits_amount_;
                            }
                        } else {
                            // in this case, first bit of component is a normal input bit
                            if (bits_amount_ > bits_per_first_gate) {
                                return (bits_per_gate -
                                        (bits_amount_ - bits_per_first_gate) % bits_per_gate) % bits_per_gate;
                            } else {
                                return bits_per_first_gate - bits_amount_;
                            }
                        }
                    }

                    std::size_t sum_bits_amount_internal(std::size_t bits_amount_, bool check_bits_) const {
                        return 1 + (bits_amount_ + check_bits_ >= 2 ? bits_amount_ + check_bits_ - 2 : 0) /
                                    bits_per_gate * 2;
                    }

                public:
                    using var = typename component_type::var;

                    const std::size_t bits_amount;
                    const bool check_bits;

                    constexpr static const std::size_t bits_per_gate = 3 * WitnessesAmount - 2;
                    const std::size_t bits_per_first_gate;
                    constexpr static const std::size_t last_bit_gate_pos = 3 * WitnessesAmount - 1;

                    constexpr static const std::size_t calc_bits_per_first_gate(bool check_bits) {
                        return check_bits ? bits_per_gate : bits_per_gate + 1;
                    }

                    constexpr static const std::size_t gates_amount = 1;
                    const std::size_t rows_amount;

                    template<typename ContainerType>
                    bit_builder_component(ContainerType witness, std::uint32_t bits_amount_, bool check_bits_) :
                        component_type(witness, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>()),
                        bits_amount(bits_amount_),
                        check_bits(check_bits_),
                        bits_per_first_gate(calc_bits_per_first_gate(check_bits_)),
                        rows_amount(rows(bits_amount_, check_bits_)) {};

                    template<typename WitnessContainerType, typename ConstantContainerType,
                            typename PublicInputContainerType>
                    bit_builder_component(WitnessContainerType witness, ConstantContainerType constant,
                                          PublicInputContainerType public_input, std::uint32_t bits_amount_,
                                          bool check_bits_) :
                        component_type(witness, constant, public_input),
                        bits_amount(bits_amount_),
                        check_bits(check_bits_),
                        bits_per_first_gate(calc_bits_per_first_gate(check_bits_)),
                        rows_amount(rows(bits_amount_, check_bits_)) {};

                    bit_builder_component(
                        std::initializer_list<typename component_type::witness_container_type::value_type>
                            witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        std::uint32_t bits_amount_, bool check_bits_) :
                            component_type(witnesses, constants, public_inputs),
                            bits_amount(bits_amount_),
                            check_bits(check_bits_),
                            bits_per_first_gate(calc_bits_per_first_gate(check_bits_)),
                            rows_amount(rows(bits_amount_, check_bits_)) {};


                    std::size_t padding_bits_amount() const {
                        return padding_bits_amount_internal(bits_amount, check_bits);
                    }

                    /*
                        Returns row and column pair for each input bit.
                        Packing is done MSB first; code in generate_assignments is responsible for reversing the order if necessary.
                    */
                    std::pair<std::size_t, std::size_t> bit_position(
                            std::size_t start_row_index, std::size_t bit_num) const {
                        std::size_t sum_bits = 0;

                        sum_bits = (bit_num >= last_bit_gate_pos) *
                                    (2 + (bit_num - last_bit_gate_pos) / bits_per_gate * 2);

                        return straight_bit_position(start_row_index, bit_num + sum_bits);
                    }

                    /*
                        Returns the amount of auxillary sum bits in the component.
                    */
                    std::size_t sum_bits_amount() const {
                        return sum_bits_amount_internal(bits_amount, check_bits);
                    }

                    /*
                        Returns row and column pair for each auxillary sum bit.
                    */
                    std::pair<std::size_t, std::size_t> sum_bit_position(
                            std::size_t start_row_index, std::size_t sum_bit_num) const {
                        assert(sum_bit_num < sum_bits_amount());
                        std::size_t bit_pos = 0;

                        bit_pos = last_bit_gate_pos + (sum_bit_num / 2) * (3 * WitnessesAmount) + (sum_bit_num % 2);

                        return straight_bit_position(start_row_index, bit_pos);
                    }
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount>
                using plonk_bit_builder = bit_builder_component<crypto3::zk::snark::plonk_constraint_system<
                                                                                                BlueprintFieldType,
                                                                                                ArithmetizationParams>,
                                                                WitnessesAmount>;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount>
                void generate_assignments(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                            &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::vector<bool> &input_bits,
                        const std::uint32_t start_row_index) {

                    assert(input_bits.size() == component.bits_amount);

                    using ArithmetizationType =
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                    using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                           WitnessesAmount>::var;

                    using field_value_type = typename BlueprintFieldType::value_type;

                    std::size_t padding = 0;
                    for (; padding < component.padding_bits_amount(); padding++) {
                        auto bit_pos = component.bit_position(start_row_index, padding);
                        assignment.witness(component.W(bit_pos.second), bit_pos.first) = 0;
                    }

                    for (std::size_t i = 0; i < input_bits.size(); i++) {
                        auto bit_pos = component.bit_position(start_row_index, padding + i);
                        assignment.witness(component.W(bit_pos.second), bit_pos.first) = input_bits[i];
                    }

                    field_value_type sum = 0;
                    std::size_t bit_num = 0;
                    for (std::size_t i = 0; i < component.sum_bits_amount(); i += 2) {

                        auto sum_bit_pos = component.sum_bit_position(start_row_index, i);
                        std::size_t max_bit_num =
                            component.last_bit_gate_pos - padding + (i / 2) * component.bits_per_gate;

                        for (; bit_num < max_bit_num; bit_num++) {
                            sum = 2 * sum + input_bits[bit_num];
                        }

                        assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                        if (i != component.sum_bits_amount() - 1) {
                            auto sum_bit_pos = component.sum_bit_position(start_row_index, i + 1);
                            assignment.witness(component.W(sum_bit_pos.second), sum_bit_pos.first) = sum;
                        }
                    }
                }

                /*
                    The check_bits parameter should always be true for bit_decomposition:
                    we need to check that the output is actually bits.
                    It is optional for bit_composition: the input might have already been checked.
                */
                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                void generate_gates(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                            &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::size_t first_selector_index) {

                    using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                           WitnessesAmount>::var;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                    using gate_type = crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;

                    int row_idx = -1;
                    std::size_t col_idx = 1;
                    std::vector<constraint_type> constraints;
                    constraint_type sum_constraint;

                    sum_constraint = var(component.W(0), -1);
                    for (std::size_t bit_num = 1; bit_num < component.last_bit_gate_pos; bit_num++) {

                        sum_constraint = 2 * sum_constraint + var(component.W(col_idx), row_idx);
                        col_idx++;
                        if (col_idx % WitnessesAmount == 0) {
                            row_idx++;
                            col_idx = 0;
                        }
                    }

                    sum_constraint = sum_constraint - var(component.W(col_idx), row_idx);
                    constraints.push_back(sum_constraint);

                    if (component.check_bits) {
                        row_idx = -1;
                        col_idx = 1;

                        for (std::size_t bit_num = 1; bit_num < component.last_bit_gate_pos; bit_num++) {

                            constraints.push_back(var(component.W(col_idx), row_idx) *
                                                      (1 - var(component.W(col_idx), row_idx)));
                            col_idx++;
                            if (col_idx % WitnessesAmount == 0) {
                                row_idx++;
                                col_idx = 0;
                            }
                        }
                    }
                    gate_type gate(first_selector_index, constraints);
                    bp.add_gate(gate);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                void generate_assignments_constant(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                            &component,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::size_t start_row_index) {

                    using var = typename plonk_bit_builder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount>::var;

                    assignment.constant(component.C(0), start_row_index) = 0;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
                void generate_circuit(
                        const plonk_bit_builder<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                            &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                            &assignment,
                        const std::size_t start_row_index) {

                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;
                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                        generate_gates<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>(
                                            component, bp, assignment, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }

                    std::size_t end_row_index = start_row_index + component.rows_amount - 2;

                    assignment.enable_selector(first_selector_index,  start_row_index + 1, end_row_index, 3);

                    // copy constraints are specific to either bit_composition or bit_decomposition
                    // they are created in generate_circuit for corresponding classes
                    generate_assignments_constant<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>(
                            component, assignment, start_row_index);
                }
            }   // namespace detail
        }       // namespace components
    }           // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BIT_BUILDER_COMPONENT_HPP
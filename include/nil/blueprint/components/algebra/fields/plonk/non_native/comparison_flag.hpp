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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_COMPARISON_FLAG_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_COMPARISON_FLAG_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/detail/get_component_id.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/detail/comparison_mode.hpp>

#include <utility>
#include <type_traits>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {
            using detail::comparison_mode;

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
            class comparison_flag;

            /*
                Compares two field elements, which are both less than 2^{bits_amount}. This condition is checked.
                Outputs a flag value, depending on the comparison result.
                If you do not require a flag, use a more efficient comparison_fail component.
                Takes one gate less if bits_amount is divisible by chunk_size.

                bits_amount should be less than BlueprintFieldType::modulus_bits.
                This component can be used in multiple modes:
                a) Outputs a flag, depending on comparison result:
                    1 if x > y.
                    0 if x = y,
                   -1 if x < y.
                b) Outputs 0 if the comparison is false, 1 otherwise.

                If we desire a flage, the comparison is performed chunkwise.
                Schematic representation of the component's primary gate for WitnessesAmount = 3:

                +--+--+--+
                |x |y |f0|
                +--+--+--+
                |c |d |t |
                +--+--+--+
                |x |y |f1|
                +--+--+--+

                x and y are chunk sums for the respective inputs, starting from 0.
                The top x, y are previous chunk sums, bottom are the current ones.
                f are the comparison bit flags, t are temporary variables, which are used to calculate f.
                c and d denote the chunks for x and y respectively.
                This gate is repeated as often as needed to compare all chunks.

                For bigger WitnessesAmount we can fit more 4-cell comparison chunks. An example for
                WitnessesAmount = 15:

                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |x |y |f0|t1|f1|t2|f2|t3|f3|t4|f4|t5|f5|t6|f6|
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |c7|d7|t7|c1|d1|c2|d2|c3|d3|c4|d4|c5|d5|c6|d6|
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |x |y |f7|  |  |  |  |  |  |  |  |  |  |  |  |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                Numbers here denote the chunk number, from most significant bits to least significant bits.
                Essentially, each comparison but the last (which is knight move shaped) is a 4-cell chunk
                (plus the previous f value).

                If WitnessesAmount divides 2, we leave a column free to the right, as we are unable to fit
                an additional comparison.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            class comparison_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                         ArithmetizationParams>,
                                                                         WitnessesAmount>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, 1, 0>;

                static std::size_t rows(std::size_t bits_amount) {
                    return (bits_amount + bits_per_gate_instance - 1) /
                           bits_per_gate_instance * 2 + 1 + needs_bonus_row;
                }

                static std::size_t gate_instances_init(std::size_t bits_amount) {
                    return (rows(bits_amount) - 1 ) / 2;
                }

                static std::size_t padded_chunks_init(std::size_t bits_amount) {
                    return gate_instances_init(bits_amount) * comparisons_per_gate_instance;
                }

                static std::size_t padding_bits_init(std::size_t bits_amount) {
                    return padded_chunks_init(bits_amount) * chunk_size - bits_amount;
                }

                static std::size_t padding_size_init(std::size_t bits_amount) {
                    return padding_bits_init(bits_amount) / chunk_size;
                }

                static std::size_t gates(std::size_t bits_amount) {
                    return 2 + (bits_amount % chunk_size > 0);
                }

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t chunk_size = 2;

                constexpr static const std::size_t comparisons_per_gate_instance = 1 + (WitnessesAmount - 3) / 2;
                constexpr static const std::size_t bits_per_gate_instance = comparisons_per_gate_instance * chunk_size;
                constexpr static const bool needs_bonus_row = (WitnessesAmount <= 3);

                const std::size_t bits_amount;
                const comparison_mode mode;

                const std::size_t rows_amount;

                const std::size_t gate_instances;
                const std::size_t padded_chunks;
                const std::size_t padding_bits;
                const std::size_t padding_size;

                const std::size_t gates_amount;

                struct input_type {
                    var x, y;
                };

                struct result_type {
                    var flag;
                    result_type(const comparison_flag &component, std::size_t start_row_index) {
                        std::size_t outuput_w = needs_bonus_row ? 0 : 3;
                        flag = var(component.W(outuput_w), start_row_index + component.rows_amount - 1, false);
                    }
                };

                nil::blueprint::detail::blueprint_component_id_type get_id() const override {
                    std::stringstream ss;
                    ss << "_" << WitnessesAmount << "_" << bits_amount << "_" << mode;
                    return ss.str();
                }

                #define __comparison_flag_init_macro(bits_amount_, mode_) \
                    bits_amount(bits_amount_), \
                    mode(mode_), \
                    rows_amount(rows(bits_amount_)), \
                    gate_instances(gate_instances_init(bits_amount_)), \
                    padded_chunks(padded_chunks_init(bits_amount_)), \
                    padding_bits(padding_bits_init(bits_amount_)), \
                    padding_size(padding_size_init(bits_amount_)), \
                    gates_amount(gates(bits_amount_))

                template<typename ContainerType>
                    comparison_flag(ContainerType witness, std::size_t bits_amount_, comparison_mode mode_):
                        component_type(witness, {}, {}),
                        __comparison_flag_init_macro(bits_amount_, mode_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                    comparison_flag(WitnessContainerType witness, ConstantContainerType constant,
                                    PublicInputContainerType public_input,
                                    std::size_t bits_amount_, comparison_mode mode_):
                        component_type(witness, constant, public_input),
                        __comparison_flag_init_macro(bits_amount_, mode_) {};

                comparison_flag(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t bits_amount_, comparison_mode mode_) :
                        component_type(witnesses, constants, public_inputs),
                        __comparison_flag_init_macro(bits_amount_, mode_) {};

                #undef __comparison_flag_init_macro
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount>
            using plonk_comparison_flag =
                comparison_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>,
                                WitnessesAmount>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>::result_type
                generate_circuit(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                        ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessesAmount>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;

                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }

                    assignment.enable_selector(first_selector_index, start_row_index + 1,
                                               start_row_index + component.rows_amount - 2 - component.needs_bonus_row, 2);

                    assignment.enable_selector(first_selector_index + 1, start_row_index + component.rows_amount - 1);

                    if (component.bits_amount % component.chunk_size != 0) {
                        assignment.enable_selector(first_selector_index + 2, start_row_index + 1);
                    }

                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                    generate_assignments_constants(component, assignment, instance_input, start_row_index);

                    return typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                          WitnessesAmount>::result_type(
                                component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount>::result_type
                generate_assignments(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams, WitnessesAmount>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessesAmount>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    std::size_t row = start_row_index;

                    using component_type = plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                                 WitnessesAmount>;
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using chunk_type = std::uint8_t;
                    BOOST_ASSERT(component.chunk_size <= 8);

                    value_type x = var_value(assignment, instance_input.x),
                               y = var_value(assignment, instance_input.y);

                    std::array<integral_type, 2> integrals = {integral_type(x.data), integral_type(y.data)};

                    std::array<std::vector<bool>, 2> bits;
                    for (std::size_t i = 0; i < 2; i++) {
                        std::fill(bits[i].begin(), bits[i].end(), false);
                        bits[i].resize(component.bits_amount + component.padding_bits);

                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::modulus_bits> bytes_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integrals[i], status);
                        std::copy(bytes_all.end() - component.bits_amount, bytes_all.end(),
                                bits[i].begin() + component.padding_bits);
                        assert(status == nil::marshalling::status_type::success);
                    }

                    BOOST_ASSERT(component.padded_chunks * component.chunk_size ==
                                 component.bits_amount + component.padding_bits);
                    std::array<std::vector<chunk_type>, 2> chunks;
                    for (std::size_t i = 0; i < 2; i++) {
                        chunks[i].resize(component.padded_chunks);
                        for (std::size_t j = 0; j < component.padded_chunks; j++) {
                            chunk_type chunk_value = 0;
                            for (std::size_t k = 0; k < component.chunk_size; k++) {
                                chunk_value <<= 1;
                                chunk_value |= bits[i][j * component.chunk_size + k];
                            }
                            chunks[i][j] = chunk_value;
                        }
                    }

                    assignment.witness(component.W(0), row) = assignment.witness(component.W(1), row)
                                                            = assignment.witness(component.W(2), row) = 0;

                    value_type greater_val = - value_type(2).pow(component.chunk_size),
                               last_flag = 0;
                    std::array<value_type, 2> sum = {0, 0};

                    for (std::size_t i = 0; i < component.gate_instances; i++) {
                        std::array<chunk_type, 2> current_chunk = {0, 0};
                        std::size_t base_idx, chunk_idx;

                        // I basically used lambdas instead of macros to cut down on code reuse.
                        // Note that the captures are by reference!
                        auto calculate_flag = [&current_chunk, &greater_val, &component](value_type last_flag) {
                            return last_flag != 0 ? last_flag
                                                  : (current_chunk[0] > current_chunk[1] ? 1
                                                  : current_chunk[0] == current_chunk[1] ? 0 : greater_val);
                        };
                        auto calculate_temp = [&current_chunk](value_type last_flag) {
                            return last_flag != 0 ? last_flag : current_chunk[0] - current_chunk[1];
                        };
                        // WARNING: this one is impure! But the code after it gets to look nicer.
                        auto place_chunk_pair = [&current_chunk, &chunks, &sum, &component, &row, &assignment](
                                            std::size_t base_idx, std::size_t chunk_idx) {
                            for (std::size_t k = 0; k < 2; k++) {
                                current_chunk[k] = chunks[k][chunk_idx];

                                assignment.witness(component.W(base_idx + k), row + 1) = current_chunk[k];
                                sum[k] *= (1 << component.chunk_size);
                                sum[k] += current_chunk[k];
                            }
                        };

                        for (std::size_t j = 0; j < component.comparisons_per_gate_instance - 1; j++) {
                            base_idx = 3 + j * 2;
                            chunk_idx = i * component.comparisons_per_gate_instance + j;

                            place_chunk_pair(base_idx, chunk_idx);
                            assignment.witness(component.W(base_idx), row) = calculate_temp(last_flag);
                            assignment.witness(component.W(base_idx + 1), row) = last_flag = calculate_flag(last_flag);
                        }
                        // Last chunk
                        base_idx = 0;
                        chunk_idx = i * component.comparisons_per_gate_instance +
                                    component.comparisons_per_gate_instance - 1;

                        place_chunk_pair(base_idx, chunk_idx);

                        assignment.witness(component.W(2), row + 1) = calculate_temp(last_flag);
                        assignment.witness(component.W(2), row + 2) = last_flag = calculate_flag(last_flag);
                        row += 2;
                        assignment.witness(component.W(0), row) = sum[0];
                        assignment.witness(component.W(1), row) = sum[1];
                    }
                    value_type output;
                    switch (component.mode) {
                        case comparison_mode::FLAG:
                            output = last_flag != greater_val ? last_flag : -1;
                            break;
                        case comparison_mode::LESS_THAN:
                            output = last_flag == greater_val;
                            break;
                        case comparison_mode::LESS_EQUAL:
                            output = (last_flag == greater_val) || (last_flag == 0);
                            break;
                        case comparison_mode::GREATER_THAN:
                            output = last_flag == 1;
                            break;
                        case comparison_mode::GREATER_EQUAL:
                            output = (last_flag == 1) || (last_flag == 0);
                            break;
                    }
                    if (!component.needs_bonus_row) {
                        assignment.witness(component.W(3), row) = output;
                    } else {
                        row++;
                        assignment.witness(component.W(0), row) = output;
                    }
                    row++;

                    BOOST_ASSERT(row == start_row_index + component.rows_amount);

                    return typename component_type::result_type(component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                void generate_gates(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                        ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessesAmount>::input_type
                        &instance_input,
                    const std::size_t first_selector_index) {

                    using var = typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                               WitnessesAmount>::var;
                    using value_type = typename BlueprintFieldType::value_type;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                    using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType,
                                                    crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>;

                    value_type base_two = 2,
                               greater_val = -base_two.pow(component.chunk_size),
                               sum_shift = base_two.pow(component.chunk_size);
                    std::vector<constraint_type> constraints;

                    auto generate_chunk_size_constraint = [](var v, std::size_t size) {
                        constraint_type constraint = v;
                        for (std::size_t i = 1; i < (1 << size); i++) {
                            constraint = constraint * (v - i);
                        }
                        return constraint;
                    };
                    auto generate_flag_values_constraint = [&greater_val](var v) {
                        constraint_type constraint = v * (v - 1) * (v - greater_val);
                        return constraint;
                    };
                    auto generate_t_update_rule = [&greater_val](var t, var f, var c, var d) {
                        constraint_type constraint = t - ((c - d) * (1 - f) * (f - greater_val) *
                                                          (-1 / greater_val) + f);
                        return constraint;
                    };
                    auto generate_t_f_constraint = [&greater_val](var t, var f) {
                        constraint_type constraint = t * (f - 1) * (f - greater_val);
                        return constraint;
                    };
                    auto generate_difference_constraint = [](var t, var f, std::size_t size) {
                        constraint_type constraint = t - f;
                        for (std::size_t i = 1; i < (1 << size); i++) {
                            constraint = constraint * (t - f - i);
                        }
                        return constraint;
                    };

                    // Assert chunk size.
                    for (std::size_t i = 0; i < component.comparisons_per_gate_instance; i++) {
                        constraint_type chunk_range_constraint =
                            generate_chunk_size_constraint(var(component.W(2 * i + (i != 0)), 0, true),
                                                           component.chunk_size);
                        constraints.push_back(bp.add_constraint(chunk_range_constraint));

                        chunk_range_constraint =
                            generate_chunk_size_constraint(var(component.W(2 * i + (i != 0) + 1), 0, true),
                                                           component.chunk_size);
                        constraints.push_back(bp.add_constraint(chunk_range_constraint));
                    }
                    // Assert flag values.
                    for (std::size_t i = 1; i < component.comparisons_per_gate_instance; i++) {
                        constraint_type flag_value_constraint =
                            generate_flag_values_constraint(var(component.W(2 + 2 * i), -1, true));
                        constraints.push_back(bp.add_constraint(flag_value_constraint));
                    }
                    constraint_type last_flag_value_constraint =
                            generate_flag_values_constraint(var(component.W(2), 1, true));
                    constraints.push_back(bp.add_constraint(last_flag_value_constraint));
                    // Assert temp and flag values update logic.
                    for (std::size_t i = 0; i < component.comparisons_per_gate_instance - 1; i++) {
                        var f_prev = var(component.W(2 + 2 * i), -1, true),
                            f_cur = var(component.W(3 + 2 * i + 1), -1, true),
                            t = var(component.W(3 + 2 * i), -1, true),
                            c = var(component.W(3 + 2 * i), 0, true),
                            d = var(component.W(3 + 2 * i + 1), 0, true);
                        constraint_type t_update_rule = generate_t_update_rule(t, f_prev, c, d);
                        constraints.push_back(bp.add_constraint(t_update_rule));

                        constraint_type t_f_constraint = generate_t_f_constraint(t, f_cur);
                        constraints.push_back(bp.add_constraint(t_f_constraint));

                        constraint_type difference_constraint =
                            generate_difference_constraint(t, f_cur, component.chunk_size);
                        constraints.push_back(bp.add_constraint(difference_constraint));
                    }
                    var last_f_prev = var(component.W(2 + 2 * (component.comparisons_per_gate_instance - 1)), -1, true),
                        last_f_cur = var(component.W(2), 1, true),
                        last_t = var(component.W(2), 0, true),
                        last_c = var(component.W(0), 0, true),
                        last_d = var(component.W(1), 0, true);
                    constraint_type last_t_update_rule = generate_t_update_rule(last_t, last_f_prev, last_c, last_d);
                    constraints.push_back(bp.add_constraint(last_t_update_rule));

                    constraint_type last_t_f_constraint = generate_t_f_constraint(last_t, last_f_cur);
                    constraints.push_back(bp.add_constraint(last_t_f_constraint));

                    constraint_type last_difference_constraint =
                        generate_difference_constraint(last_t, last_f_cur, component.chunk_size);
                    constraints.push_back(bp.add_constraint(last_difference_constraint));

                    // Assert chunk sums.
                    std::array<constraint_type, 2> sum_constraints;
                    for (std::size_t i = 0; i < 2; i++) {
                        sum_constraints[i] = var(component.W(i), -1, true);
                    }
                    for (std::size_t i = 0; i < component.comparisons_per_gate_instance - 1; i++) {
                        for (std::size_t j = 0; j < 2; j++) {
                            sum_constraints[j] = sum_shift * sum_constraints[j] +
                                                    var(component.W(3 + 2 * i + j), 0, true);
                        }
                    }
                    for (std::size_t j = 0; j < 2; j++) {
                        sum_constraints[j] = sum_shift * sum_constraints[j] + var(component.W(j), 0, true);
                        sum_constraints[j] = var(component.W(j), 1, true) - sum_constraints[j];

                        constraints.push_back(bp.add_constraint(sum_constraints[j]));
                    }

                    gate_type gate(first_selector_index, constraints);
                    bp.add_gate(gate);

                    constraint_type comparison_constraint;
                    var flag_var, output_var;
                    value_type g = greater_val,
                               g_m_1 = greater_val - 1,
                               g_g_m_1 = greater_val * (greater_val - 1);
                    // All constraints below are the appropriate Lagrange interpolation polynomials.
                    if (!component.needs_bonus_row) {
                        flag_var = var(component.W(2), 0, true);
                        output_var = var(component.W(3), 0, true);
                    } else {
                        flag_var = var(component.W(2), -1, true);
                        output_var = var(component.W(0), 0, true);
                    }
                    switch (component.mode) {
                        case comparison_mode::FLAG:
                            // This converts flag {greater_val, 0, 1} to {-1, 0, 1}.
                            comparison_constraint = output_var -
                                ((- 2 * (1 / g_g_m_1) - 1/g) * flag_var * flag_var +
                                 (2 * (1 / g_g_m_1) + 1/g + 1) * flag_var);

                            break;
                        case comparison_mode::GREATER_THAN:
                            // This converts flag {greater_val, 0, 1} to {0, 0, 1}.
                            comparison_constraint = output_var + flag_var * (flag_var - g) * (1 / g_m_1);
                            break;
                        case comparison_mode::GREATER_EQUAL:
                            // This converts flag {greater_val, 0, 1} to {0, 1, 1}.
                            comparison_constraint = output_var +
                                                    (flag_var - g) * (flag_var - (1 - g)) * (1 / g_g_m_1);
                            break;
                        case comparison_mode::LESS_THAN:
                            // This converts flag {greater_val, 0, 1} to {1, 0, 0}.
                            comparison_constraint = output_var - flag_var * (flag_var - 1) * (1 / g_g_m_1);
                            break;
                        case comparison_mode::LESS_EQUAL:
                            // This converts flag {greater_val, 0, 1} to {1, 1, 0}.
                            comparison_constraint = output_var - (1 - flag_var * (flag_var - g) * (1/(-g_m_1)));
                            break;
                    }
                    gate = gate_type(first_selector_index + 1, comparison_constraint);
                    bp.add_gate(gate);

                    if (component.bits_amount % component.chunk_size == 0) return;
                    // If bits_amount is not divisible by chunk size, the first chunk of x/y should be constrained to
                    // be less than 2^{bits_amount % component.chunk_size}
                    // These constraints cannot be skipped: otherwise,
                    // we don't check that x and y fit into 2^{bits_amount}.
                    std::vector<constraint_type> first_chunk_range_constraints;

                    var size_constraint_var = var(component.W(3 + 2 * component.padding_size), 0, true);
                    constraint_type first_chunk_range_constraint = generate_chunk_size_constraint(
                        size_constraint_var, component.bits_amount % component.chunk_size);
                    first_chunk_range_constraints.push_back(first_chunk_range_constraint);

                    size_constraint_var = var(component.W(3 + 2 * component.padding_size + 1), 0, true);
                    first_chunk_range_constraint =
                        generate_chunk_size_constraint(size_constraint_var,
                                                       component.bits_amount % component.chunk_size);
                    first_chunk_range_constraints.push_back(first_chunk_range_constraint);

                    gate = gate_type(first_selector_index + 2, first_chunk_range_constraints);
                    bp.add_gate(gate);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                void generate_copy_constraints(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                        ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                    WitnessesAmount>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    using var = typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                               WitnessesAmount>::var;

                    std::size_t row = start_row_index;
                    var zero(0, start_row_index, false, var::column_type::constant);
                    for (std::size_t i = 0; i < 3; i++) {
                        bp.add_copy_constraint({zero, var(component.W(i), row, false)});
                    }
                    row++;
                    for (std::size_t i = 0; i < component.padding_size; i++) {
                        bp.add_copy_constraint({zero, var(component.W(3 + 2 * i), row, false)});
                        bp.add_copy_constraint({zero, var(component.W(3 + 2 * i + 1), row, false)});
                    }
                    row = start_row_index + component.rows_amount - 1 - component.needs_bonus_row;
                    bp.add_copy_constraint({instance_input.x, var(component.W(0), row, false)});
                    bp.add_copy_constraint({instance_input.y, var(component.W(1), row, false)});
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                         std::enable_if_t<WitnessesAmount >= 3, bool> = true>
                void generate_assignments_constants(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                WitnessesAmount>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams,
                                                     WitnessesAmount>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    assignment.constant(component.C(0), start_row_index) = 0;
                }

        }   // namespace components
    }       // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_COMPARISON_FLAG_HPP

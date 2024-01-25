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
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_mode.hpp>

#include <utility>
#include <type_traits>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
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

                If we desire a flag, the comparison is performed chunkwise.
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
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class comparison_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                              ArithmetizationParams>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                static std::size_t comparisons_per_gate_instance_internal(std::size_t witness_amount) {
                    return 1 + (witness_amount - 3) / 2;
                }

                static std::size_t bits_per_gate_instance_internal(std::size_t witness_amount) {
                    return comparisons_per_gate_instance_internal(witness_amount) * chunk_size;
                }

                static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return (bits_amount + bits_per_gate_instance_internal(witness_amount) - 1) /
                           bits_per_gate_instance_internal(witness_amount) * 2 +
                           1 + needs_bonus_row_internal(witness_amount);
                }

                static std::size_t gate_instances_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return (rows_amount_internal(witness_amount, bits_amount) - 1) / 2;
                }

                static std::size_t padded_chunks_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return gate_instances_internal(witness_amount, bits_amount) *
                            comparisons_per_gate_instance_internal(witness_amount);
                }

                static std::size_t padding_bits_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return padded_chunks_internal(witness_amount, bits_amount) * chunk_size - bits_amount;
                }

                static std::size_t padding_size_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return padding_bits_internal(witness_amount, bits_amount) / chunk_size;
                }

                static std::size_t gates_amount_internal(std::size_t bits_amount) {
                    return 2 + (bits_amount % chunk_size > 0);
                }

                static std::size_t needs_bonus_row_internal(std::size_t witness_amount) {
                    return witness_amount <= 3;
                }

                void check_params(std::size_t bits_amount, comparison_mode mode) const {
                    BLUEPRINT_RELEASE_ASSERT(bits_amount > 0 && bits_amount < BlueprintFieldType::modulus_bits );
                    BLUEPRINT_RELEASE_ASSERT(mode == comparison_mode::LESS_THAN ||
                                             mode == comparison_mode::GREATER_THAN ||
                                             mode == comparison_mode::LESS_EQUAL ||
                                             mode == comparison_mode::GREATER_EQUAL ||
                                             mode == comparison_mode::FLAG);
                }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    std::size_t bits_amount;
                    comparison_mode mode;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t bits_amount_,
                                       comparison_mode mode_)
                        : witness_amount(witness_amount_), bits_amount(bits_amount_), mode(mode_) {}

                    std::uint32_t gates_amount() const override {
                        return comparison_flag::gates_amount_internal(bits_amount);
                    }

                    bool operator<(const component_gate_manifest* other) const override{
                        const gate_manifest_type* other_casted = dynamic_cast<const gate_manifest_type*>(other);
                        return witness_amount < other_casted->witness_amount ||
                               (witness_amount == other_casted->witness_amount &&
                                bits_amount < other_casted->bits_amount) ||
                               (witness_amount == other_casted->witness_amount &&
                                bits_amount == other_casted->bits_amount &&
                                mode < other_casted->mode);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t bits_amount,
                                                       comparison_mode mode) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount, bits_amount, mode));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(3, (BlueprintFieldType::modulus_bits + 28 - 1) / 28 )),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t bits_amount,
                                                             comparison_mode mode) {
                    return rows_amount_internal(witness_amount, bits_amount);
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 1;
                }

                /*
                   It's CRITICAL that these three variables remain on top
                   Otherwise initialization goes in wrong order, leading to arbitrary values.
                */
                const std::size_t bits_amount;
                const comparison_mode mode;
                constexpr static const std::size_t chunk_size = 2;
                /* Do NOT move the above variables! */

                const std::size_t comparisons_per_gate_instance =
                    comparisons_per_gate_instance_internal(this->witness_amount());
                const std::size_t bits_per_gate_instance =
                    bits_per_gate_instance_internal(this->witness_amount());
                const bool needs_bonus_row = needs_bonus_row_internal(this->witness_amount());

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), bits_amount);
                const std::size_t empty_rows_amount = get_empty_rows_amount();

                const std::size_t gate_instances = gate_instances_internal(this->witness_amount(), bits_amount);
                const std::size_t padded_chunks = padded_chunks_internal(this->witness_amount(), bits_amount);
                const std::size_t padding_bits = padding_bits_internal(this->witness_amount(), bits_amount);
                const std::size_t padding_size = padding_size_internal(this->witness_amount(), bits_amount);

                const std::size_t gates_amount = gates_amount_internal(bits_amount);
                const std::string component_name = "comparison (==, !=)";

                struct input_type {
                    var x, y;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x, y};
                    }
                };

                struct result_type {
                    var flag;
                    result_type(const comparison_flag &component, std::size_t start_row_index) {
                        std::size_t outuput_w = component.needs_bonus_row ? 0 : 3;
                        flag = var(component.W(outuput_w), start_row_index + component.rows_amount - 1, false);
                    }
                    result_type(const comparison_flag &component, std::size_t start_row_index, bool skip) {
                        flag = var(component.W(0), start_row_index, false);
                    }

                    std::vector<var> all_vars() const {
                        return {flag};
                    }
                };

                template<typename ContainerType>
                explicit comparison_flag(ContainerType witness, std::size_t bits_amount_, comparison_mode mode_):
                        component_type(witness, {}, {}, get_manifest()),
                        bits_amount(bits_amount_),
                        mode(mode_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                    comparison_flag(WitnessContainerType witness, ConstantContainerType constant,
                                    PublicInputContainerType public_input,
                                    std::size_t bits_amount_, comparison_mode mode_):
                        component_type(witness, constant, public_input, get_manifest()),
                        bits_amount(bits_amount_),
                        mode(mode_) {

                    check_params(bits_amount, mode);
                };

                comparison_flag(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t bits_amount_, comparison_mode mode_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        bits_amount(bits_amount_),
                        mode(mode_) {

                    check_params(bits_amount, mode);
                };

                static typename BlueprintFieldType::value_type calculate(std::size_t witness_amount,
                                                                         typename BlueprintFieldType::value_type x,
                                                                         typename BlueprintFieldType::value_type y,
                                                                         std::size_t arg_bits_amount, comparison_mode arg_mode) {

                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using chunk_type = std::uint8_t;

                    auto chunk_size = 2;
                    auto padding_bits = padding_bits_internal(witness_amount, arg_bits_amount);
                    auto padded_chunks = padded_chunks_internal(witness_amount, arg_bits_amount);
                    auto comparisons_per_gate_instance = comparisons_per_gate_instance_internal(witness_amount);
                    auto gate_instances = gate_instances_internal(witness_amount, arg_bits_amount);

                    BOOST_ASSERT(chunk_size <= 8);

                    std::array<integral_type, 2> integrals = {integral_type(x.data), integral_type(y.data)};

                    std::array<std::vector<bool>, 2> bits;
                    for (std::size_t i = 0; i < 2; i++) {
                        std::fill(bits[i].begin(), bits[i].end(), false);
                        bits[i].resize(arg_bits_amount + padding_bits);

                        nil::marshalling::status_type status;
                        std::array<bool, BlueprintFieldType::modulus_bits> bytes_all =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integrals[i], status);
                        std::copy(bytes_all.end() - arg_bits_amount, bytes_all.end(),
                                bits[i].begin() + padding_bits);
                        assert(status == nil::marshalling::status_type::success);
                    }

                    BOOST_ASSERT(padded_chunks * chunk_size ==
                                 arg_bits_amount + padding_bits);
                    std::array<std::vector<chunk_type>, 2> chunks;
                    for (std::size_t i = 0; i < 2; i++) {
                        chunks[i].resize(padded_chunks);
                        for (std::size_t j = 0; j < padded_chunks; j++) {
                            chunk_type chunk_value = 0;
                            for (std::size_t k = 0; k < std::size_t(chunk_size); k++) {
                                chunk_value <<= 1;
                                chunk_value |= bits[i][j * chunk_size + k];
                            }
                            chunks[i][j] = chunk_value;
                        }
                    }

                    value_type greater_val = - value_type(2).pow(chunk_size),
                               last_flag = 0;
                    std::array<value_type, 2> sum = {0, 0};

                    for (std::size_t i = 0; i < gate_instances; i++) {
                        std::array<chunk_type, 2> current_chunk = {0, 0};
                        std::size_t base_idx, chunk_idx;

                        // I basically used lambdas instead of macros to cut down on code reuse.
                        // Note that the captures are by reference!
                        auto calculate_flag = [&current_chunk, &greater_val](value_type last_flag) {
                            return last_flag != 0 ? last_flag
                                                  : (current_chunk[0] > current_chunk[1] ? 1
                                                  : current_chunk[0] == current_chunk[1] ? 0 : greater_val);
                        };
                        // WARNING: this one is impure! But the code after it gets to look nicer.
                        auto place_chunk_pair = [&current_chunk, &chunks, &sum, &chunk_size](
                                            std::size_t base_idx, std::size_t chunk_idx) {
                            for (std::size_t k = 0; k < 2; k++) {
                                current_chunk[k] = chunks[k][chunk_idx];
                                sum[k] *= (1 << chunk_size);
                                sum[k] += current_chunk[k];
                            }
                        };

                        for (std::size_t j = 0; j < comparisons_per_gate_instance - 1; j++) {
                            base_idx = 3 + j * 2;
                            chunk_idx = i * comparisons_per_gate_instance + j;

                            place_chunk_pair(base_idx, chunk_idx);
                            last_flag = calculate_flag(last_flag);
                        }
                        // Last chunk
                        base_idx = 0;
                        chunk_idx = i * comparisons_per_gate_instance +
                                    comparisons_per_gate_instance - 1;

                        place_chunk_pair(base_idx, chunk_idx);
                        last_flag = calculate_flag(last_flag);
                    }
                    value_type output;
                    switch (arg_mode) {
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

                    return output;
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_comparison_flag =
                comparison_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                        ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    std::vector<std::size_t> selector_indices =
                        generate_gates(component, bp, assignment, instance_input);

                    assignment.enable_selector(selector_indices[0], start_row_index + 1,
                                               start_row_index + component.rows_amount - 2 - component.needs_bonus_row, 2);

                    assignment.enable_selector(selector_indices[1], start_row_index + component.rows_amount - 1);

                    if (component.bits_amount % component.chunk_size != 0) {
                        if (selector_indices.size() != 3) {
                            std::cerr << "Internal error: comparison_flag component returned the wrong selector amount."
                                      << std::endl;
                            std::abort();
                        }
                        assignment.enable_selector(selector_indices[2], start_row_index + 1);
                    }

                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                    generate_assignments_constants(component, assignment, instance_input, start_row_index);

                    return typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::result_type(
                                component, start_row_index);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    std::size_t row = start_row_index;

                    using component_type = plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>;
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
                        auto calculate_flag = [&current_chunk, &greater_val](value_type last_flag) {
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

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_empty_assignments(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    using component_type = plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>;
                    using value_type = typename BlueprintFieldType::value_type;

                    value_type x = var_value(assignment, instance_input.x),
                               y = var_value(assignment, instance_input.y);

                    assignment.witness(component.W(0), start_row_index) =
                            component_type::calculate(component.witness_amount(), x, y, component.bits_amount, component.mode);

                    return typename component_type::result_type(component, start_row_index, true);
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                std::vector<std::size_t> generate_gates(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                        ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input) {

                    using var = typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::var;
                    using value_type = typename BlueprintFieldType::value_type;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                    std::vector<std::size_t> selector_indices;

                    value_type base_two = 2,
                               greater_val = -base_two.pow(component.chunk_size),
                               sum_shift = base_two.pow(component.chunk_size);
                    std::vector<constraint_type> constraints;

                    auto generate_chunk_size_constraint = [](var v, std::size_t size) {
                        constraint_type constraint = v;
                        for (std::size_t i = 1; i < std::size_t(1 << size); i++) {
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
                        for (std::size_t i = 1; i < std::size_t(1 << size); i++) {
                            constraint = constraint * (t - f - i);
                        }
                        return constraint;
                    };

                    // Assert chunk size.
                    for (std::size_t i = 0; i < component.comparisons_per_gate_instance; i++) {
                        constraint_type chunk_range_constraint =
                            generate_chunk_size_constraint(var(component.W(2 * i + (i != 0)), 0, true),
                                                           component.chunk_size);
                        constraints.push_back(chunk_range_constraint);

                        chunk_range_constraint =
                            generate_chunk_size_constraint(var(component.W(2 * i + (i != 0) + 1), 0, true),
                                                           component.chunk_size);
                        constraints.push_back(chunk_range_constraint);
                    }
                    // Assert flag values.
                    for (std::size_t i = 1; i < component.comparisons_per_gate_instance; i++) {
                        constraint_type flag_value_constraint =
                            generate_flag_values_constraint(var(component.W(2 + 2 * i), -1, true));
                        constraints.push_back(flag_value_constraint);
                    }
                    constraint_type last_flag_value_constraint =
                            generate_flag_values_constraint(var(component.W(2), 1, true));
                    constraints.push_back(last_flag_value_constraint);
                    // Assert temp and flag values update logic.
                    for (std::size_t i = 0; i < component.comparisons_per_gate_instance - 1; i++) {
                        var f_prev = var(component.W(2 + 2 * i), -1, true),
                            f_cur = var(component.W(3 + 2 * i + 1), -1, true),
                            t = var(component.W(3 + 2 * i), -1, true),
                            c = var(component.W(3 + 2 * i), 0, true),
                            d = var(component.W(3 + 2 * i + 1), 0, true);
                        constraint_type t_update_rule = generate_t_update_rule(t, f_prev, c, d);
                        constraints.push_back(t_update_rule);

                        constraint_type t_f_constraint = generate_t_f_constraint(t, f_cur);
                        constraints.push_back(t_f_constraint);

                        constraint_type difference_constraint =
                            generate_difference_constraint(t, f_cur, component.chunk_size);
                        constraints.push_back(difference_constraint);
                    }
                    var last_f_prev = var(component.W(2 + 2 * (component.comparisons_per_gate_instance - 1)), -1, true),
                        last_f_cur = var(component.W(2), 1, true),
                        last_t = var(component.W(2), 0, true),
                        last_c = var(component.W(0), 0, true),
                        last_d = var(component.W(1), 0, true);
                    constraint_type last_t_update_rule = generate_t_update_rule(last_t, last_f_prev, last_c, last_d);
                    constraints.push_back(last_t_update_rule);

                    constraint_type last_t_f_constraint = generate_t_f_constraint(last_t, last_f_cur);
                    constraints.push_back(last_t_f_constraint);

                    constraint_type last_difference_constraint =
                        generate_difference_constraint(last_t, last_f_cur, component.chunk_size);
                    constraints.push_back(last_difference_constraint);

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

                        constraints.push_back(sum_constraints[j]);
                    }

                    selector_indices.push_back(bp.add_gate(constraints));

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
                    selector_indices.push_back(bp.add_gate(comparison_constraint));

                    if (component.bits_amount % component.chunk_size == 0) return selector_indices;
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

                    selector_indices.push_back(bp.add_gate(first_chunk_range_constraints));
                    return selector_indices;
                }

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_copy_constraints(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                        ArithmetizationParams>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    using var = typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::var;

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

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_assignments_constants(
                    const plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>>
                        &assignment,
                    const typename plonk_comparison_flag<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                    assignment.constant(component.C(0), start_row_index) = 0;
                }

        }   // namespace components
    }       // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_COMPARISON_FLAG_HPP

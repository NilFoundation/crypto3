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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_NON_NATIVE_COMPARISON_CHECKED_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_NON_NATIVE_COMPARISON_CHECKED_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_mode.hpp>

#include <type_traits>
#include <utility>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
            class comparison_checked;

            /*
                Compare x and y, failing if the comparsion is not satisfied.
                Both x and y have to fit in bits_amount bits; this condition is checked. See comparsion_unchecked
                Additionally, bits_amount has to satisfy: bits_amount < modulus_bits - 1.
                Takes one gate less for bits_amount divisible by chunk_size.

                For less, we check that both x and x - y are less than 2^{bits_amount}.
                The check is done by splitting x (x-y) into bit chunks and checking that their weighted sum is
                equal to x (x-y). After that, we add a constraint checking for non-zero x - y.
                Other comparsion modes are implemented similarly.

                The component is multiple copies of the following gate (illustrated for WitnessesAmount = 15):
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |x|d|p|p|p|p|p|p|p|p|p|p|p|p|p|
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |p|o|o|o|o|o|o|o|o|o|o|o|o|o|o|
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |x|d| | | | | | | | | | | | | |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                Where x and d are weighted sum of bit chunks for x and y - x respectively, and o/p are the bit chunks
                of x and y - x respectively. Empty spaces are not constrained.
                Starting sums for x and d are constrained to be zero.
                We use the third cell in the final row to store y, and use it to check that the difference is correct.

                See comparison_flag if you want to access the result of the comparison instead.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class comparison_checked<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                using value_type = typename BlueprintFieldType::value_type;

                static std::size_t chunk_amount_internal(std::size_t bits_amount) {
                    return (bits_amount + chunk_size - 1) / chunk_size;
                }
                // We need to pad each of x, y - x up to the nearest multiple of WitnessAmount - 1.
                static std::size_t padded_chunks_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return (chunk_amount_internal(bits_amount) + witness_amount - 2) /
                            (witness_amount - 1) * (witness_amount - 1);
                }

                static std::size_t padding_size_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return padded_chunks_internal(witness_amount, bits_amount) - chunk_amount_internal(bits_amount);
                }

                static std::size_t padding_bits_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return padded_chunks_internal(witness_amount, bits_amount) * chunk_size - bits_amount;
                }

                static bool needs_bonus_row_internal(std::size_t witness_amount, comparison_mode mode) {
                    return witness_amount <= 3 &&
                           (mode == comparison_mode::LESS_THAN ||
                            mode == comparison_mode::GREATER_THAN);
                }

                static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t bits_amount,
                                                        comparison_mode mode) {
                    return 1 + 2 * padded_chunks_internal(witness_amount, bits_amount) / (witness_amount - 1) +
                           needs_bonus_row_internal(witness_amount, mode);
                }

                static bool needs_first_chunk_constraint_internal(std::size_t bits_amount) {
                    return (bits_amount % chunk_size) &&
                           (bits_amount + ((chunk_size - bits_amount % chunk_size) % chunk_size) >=
                                BlueprintFieldType::modulus_bits - 1);
                }

                static std::size_t gates_amount_internal(std::size_t bits_amount, comparison_mode mode) {
                    return 2 + needs_first_chunk_constraint_internal(bits_amount);
                }

                static std::size_t chunks_per_row_internal(std::size_t witness_amount) {
                    return witness_amount - 1;
                }

                static std::size_t bits_per_row_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return chunks_per_row_internal(witness_amount) * chunk_size;
                }

                void check_params(std::size_t bits_amount, comparison_mode mode) const {
                    BLUEPRINT_RELEASE_ASSERT(bits_amount > 0 && bits_amount < BlueprintFieldType::modulus_bits - 1);
                    BLUEPRINT_RELEASE_ASSERT(mode == comparison_mode::LESS_THAN ||
                                             mode == comparison_mode::GREATER_THAN ||
                                             mode == comparison_mode::LESS_EQUAL ||
                                             mode == comparison_mode::GREATER_EQUAL);
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

                    gate_manifest_type(std::size_t witness_amount_, std::size_t bits_amount_, comparison_mode mode_)
                        : witness_amount(witness_amount_), bits_amount(bits_amount_), mode(mode_) {}

                    std::uint32_t gates_amount() const override {
                        return comparison_checked::gates_amount_internal(bits_amount, mode);
                    }

                    bool operator<(gate_manifest_type const& other) const {
                        return witness_amount < other.witness_amount ||
                               (witness_amount == other.witness_amount && bits_amount < other.bits_amount) ||
                               (witness_amount == other.witness_amount &&
                                bits_amount == other.bits_amount && mode < other.mode);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t bits_amount,
                                                       comparison_mode mode) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, bits_amount, mode));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(
                                3, (BlueprintFieldType::modulus_bits - 1 + chunk_size - 1) / chunk_size)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t bits_amount,
                                                             comparison_mode mode) {
                    return rows_amount_internal(witness_amount, bits_amount, mode);
                }

                /*
                   It's CRITICAL that these three variables remain on top
                   Otherwise initialization goes in wrong order, leading to arbitrary values.
                */
                const std::size_t bits_amount;
                const comparison_mode mode;
                constexpr static const std::size_t chunk_size = 2;
                /* Do NOT move the above variables! */

                const std::size_t chunk_amount = chunk_amount_internal(bits_amount);
                // Techincally, this is average chunks per row after first.
                const std::size_t chunks_per_row = chunks_per_row_internal(this->witness_amount());
                const std::size_t bits_per_row = bits_per_row_internal(this->witness_amount(), bits_amount);

                const std::size_t padded_chunks = padded_chunks_internal(this->witness_amount(), bits_amount);
                const std::size_t padding_size = padding_size_internal(this->witness_amount(), bits_amount);
                const std::size_t padding_bits = padding_bits_internal(this->witness_amount(), bits_amount);

                const bool needs_bonus_row = needs_bonus_row_internal(this->witness_amount(), mode);
                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), bits_amount, mode);
                const bool needs_first_chunk_constraint = needs_first_chunk_constraint_internal(bits_amount);
                const std::size_t gates_amount = gates_amount_internal(bits_amount, mode);

                struct input_type {
                    var x, y;

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    result_type(const comparison_checked &component, std::size_t start_row_index) {}

                    std::vector<var> all_vars() const {
                        return {};
                    }
                };

                template <typename ContainerType>
                    comparison_checked(ContainerType witness, std::size_t bits_amount_, comparison_mode mode_):
                        component_type(witness, {}, {}, get_manifest()),
                        bits_amount(bits_amount_),
                        mode(mode_) {

                        check_params(bits_amount, mode);
                    };

                template <typename WitnessContainerType, typename ConstantContainerType,
                          typename PublicInputContainerType>
                    comparison_checked(WitnessContainerType witness, ConstantContainerType constant,
                                       PublicInputContainerType public_input,
                                       std::size_t bits_amount_, comparison_mode mode_):
                        component_type(witness, constant, public_input, get_manifest()),
                        bits_amount(bits_amount_),
                        mode(mode_) {

                    check_params(bits_amount, mode);
                };

                comparison_checked(
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
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_comparison_checked =
                comparison_checked<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::vector<std::size_t> selector_indices;

                typename BlueprintFieldType::value_type base_two = 2;
                std::vector<constraint_type> constraints;
                constraints.reserve(component.witness_amount() * 2 - 2);

                auto generate_chunk_size_constraint = [](var v, std::size_t size) {
                    constraint_type constraint = v;
                    for (std::size_t i = 1; i < (1 << size); i++) {
                        constraint = constraint * (v - i);
                    }
                    return constraint;
                };

                // Assert chunk size.
                for (std::size_t row_idx = 0; row_idx < 2; row_idx++) {
                    for (std::size_t i = 2 * (1 - row_idx); i < component.witness_amount(); i++) {
                        constraint_type chunk_range_constraint =
                            generate_chunk_size_constraint(var(component.W(i), int(row_idx) - 1, true),
                                                           component.chunk_size);

                        constraints.push_back(chunk_range_constraint);
                    }
                }
                // Assert sums. var_idx = 0 is x, var_idx = 1 is diff=y-x.
                for (int var_idx = 0; var_idx < 2; var_idx++) {
                    constraint_type sum_constraint = var(component.W(1 + var_idx), -var_idx, true);
                    for (std::size_t i = 2 + var_idx; i < component.witness_amount(); i++) {
                        sum_constraint = base_two.pow(component.chunk_size) * sum_constraint +
                                         var(component.W(i), -var_idx, true);
                    }
                    if (var_idx == 1) {
                        sum_constraint = base_two.pow(component.chunk_size) * sum_constraint +
                                         var(component.W(0), 0, true);
                    }
                    sum_constraint = sum_constraint +
                                        base_two.pow(component.chunk_size * component.chunks_per_row) *
                                                    var(component.W(var_idx), -1, true) -
                                        var(component.W(var_idx), 1, true);
                    constraints.push_back(sum_constraint);
                }

                selector_indices.push_back(bp.add_gate(constraints));

                std::vector<constraint_type> correctness_constraints;
                constraint_type diff_constraint = var(component.W(2), 0, true) - var(component.W(0), 0, true) -
                                                  var(component.W(1), 0, true),
                                non_zero_constraint;
                correctness_constraints.push_back(diff_constraint);
                switch (component.mode) {
                    case comparison_mode::GREATER_EQUAL:
                    case comparison_mode::LESS_EQUAL:
                        break;
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::GREATER_THAN:
                        if (!component.needs_bonus_row) {
                            non_zero_constraint = var(component.W(1), 0, true) * var(component.W(3), 0, true) - 1;
                        } else {
                            non_zero_constraint = var(component.W(1), 0, true) * var(component.W(0), 1, true) - 1;
                        }
                        correctness_constraints.push_back(non_zero_constraint);
                        break;
                    case comparison_mode::FLAG:
                        BOOST_ASSERT_MSG(false, "FLAG mode is not supported, use comparison_flag component instead.");
                }

                selector_indices.push_back(bp.add_gate(correctness_constraints));

                if (!component.needs_first_chunk_constraint) return selector_indices;
                // If bits_amount is not divisible by chunk size, the first chunk of both x/y - x should be constrained
                // to be less than 2^{bits_amount % component.chunk_size}.
                // We actually only need this constraint when y - x can do an unsafe overflow.
                // Otherwise the constraint on y - x takes care of this.
                std::vector<constraint_type> first_chunk_range_constraints;

                var size_constraint_var = component.padding_size != component.witness_amount() - 2 ?
                                            var(component.W(2 + component.padding_size), 0, true)
                                          : var(component.W(0), 1, true);
                constraint_type first_chunk_range_constraint = generate_chunk_size_constraint(
                    size_constraint_var, component.bits_amount % component.chunk_size);
                first_chunk_range_constraints.push_back(first_chunk_range_constraint);

                size_constraint_var = var(component.W(1 + component.padding_size), 1, true);
                first_chunk_range_constraint =
                    generate_chunk_size_constraint(size_constraint_var, component.bits_amount % component.chunk_size);
                first_chunk_range_constraints.push_back(first_chunk_range_constraint);

                selector_indices.push_back(bp.add_gate(first_chunk_range_constraints));
                return selector_indices;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::var;
                std::uint32_t row = start_row_index;
                var zero(0, start_row_index, false, var::column_type::constant);

                bp.add_copy_constraint({zero, var(component.W(0), start_row_index, false)});
                bp.add_copy_constraint({zero, var(component.W(1), start_row_index, false)});

                // Padding constraints for x
                for (std::size_t i = 0; i < component.padding_size; i++) {
                    bp.add_copy_constraint({zero, var(component.W(i + 1), start_row_index + 1, false)});
                }
                // Padding constraints for difference
                for (std::size_t i = 0; i < component.padding_size; i++) {
                    bp.add_copy_constraint({zero, var(component.W(i + 2), start_row_index, false)});
                }

                row += component.rows_amount - 1 - component.needs_bonus_row;
                var x_var = var(component.W(0), row, false),
                    y_var = var(component.W(2), row, false);
                switch (component.mode) {
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::LESS_EQUAL:
                        break;
                    case comparison_mode::GREATER_THAN:
                    case comparison_mode::GREATER_EQUAL:
                        std::swap(x_var, y_var);
                        break;
                    case comparison_mode::FLAG:
                        BOOST_ASSERT_MSG(false, "FLAG mode is not supported, use comparison_flag component instead.");
                }
                bp.add_copy_constraint({instance_input.x, x_var});
                bp.add_copy_constraint({instance_input.y, y_var});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_circuit(
                const plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::vector<std::size_t> selector_indices =
                    generate_gates(component, bp, assignment, instance_input);

                std::size_t final_gate_mid_row = start_row_index + component.rows_amount - 2 -
                                                 component.needs_bonus_row;

                assignment.enable_selector(selector_indices[0], start_row_index + 1,
                                           final_gate_mid_row, 2);
                assignment.enable_selector(selector_indices[1], final_gate_mid_row + 1);

                if (component.needs_first_chunk_constraint) {
                    if (selector_indices.size() != 3) {
                        std::cerr << "Internal error: comparison_checked component returned the wrong selector amount."
                                  << std::endl;
                        std::abort();
                    }
                    assignment.enable_selector(selector_indices[2], start_row_index);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constants(component, assignment, instance_input, start_row_index);

                return typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_assignments(
                const plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using chunk_type = std::uint8_t;
                BOOST_ASSERT(component.chunk_size <= 8);

                value_type x = var_value(assignment, instance_input.x),
                           y = var_value(assignment, instance_input.y);
                switch (component.mode) {
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::LESS_EQUAL:
                        break;
                    case comparison_mode::GREATER_THAN:
                    case comparison_mode::GREATER_EQUAL:
                        std::swap(x, y);
                        break;
                    case comparison_mode::FLAG:
                        BOOST_ASSERT_MSG(false, "FLAG mode is not supported, use comparison_flag component instead.");
                }
                value_type diff = y - x;

                std::array<integral_type, 2> integrals = {integral_type(x.data), integral_type(diff.data)};

                std::array<std::vector<bool>, 2> bits;
                for (std::size_t i = 0; i < 2; i++) {
                    bits[i].resize(component.bits_amount + component.padding_bits);
                    std::fill(bits[i].begin(), bits[i].end(), false);

                    nil::marshalling::status_type status;
                    std::array<bool, BlueprintFieldType::modulus_bits> bytes_all =
                        nil::marshalling::pack<nil::marshalling::option::big_endian>(integrals[i], status);
                    std::copy(bytes_all.end() - component.bits_amount, bytes_all.end(),
                              bits[i].begin() + component.padding_bits);
                    assert(status == nil::marshalling::status_type::success);
                }

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

                assignment.witness(component.W(0), row) = assignment.witness(component.W(1), row) = 0;

                std::array<value_type, 2> sum = {0, 0};
                for (std::size_t i = 0; i < (component.rows_amount - 1) / 2; i++) {
                    // Filling the first row.
                    for (std::size_t j = 0; j < component.chunks_per_row - 1; j++) {
                        assignment.witness(component.W(j + 2), row) =
                            chunks[1][i * component.chunks_per_row + j];
                        sum[1] *= (1 << component.chunk_size);
                        sum[1] += chunks[1][i * component.chunks_per_row + j];
                    }
                    row++;
                    // Filling the second row.
                    assignment.witness(component.W(0), row) = chunks[1][i * component.chunks_per_row +
                                                                        component.chunks_per_row - 1];
                    sum[1] *= (1 << component.chunk_size);
                    sum[1] += chunks[1][i * component.chunks_per_row + component.chunks_per_row - 1];

                    for (std::size_t j = 0; j < component.chunks_per_row; j++) {
                        assignment.witness(component.W(j + 1), row) =
                            chunks[0][i * component.chunks_per_row + j];
                        sum[0] *= (1 << component.chunk_size);
                        sum[0] += chunks[0][i * component.chunks_per_row + j];
                    }
                    row++;
                    // Filling the sums
                    assignment.witness(component.W(0), row) = sum[0];
                    assignment.witness(component.W(1), row) = sum[1];
                }
                assignment.witness(component.W(2), row) = y;
                switch (component.mode) {
                    case comparison_mode::LESS_THAN:
                    case comparison_mode::GREATER_THAN:
                        if (!component.needs_bonus_row) {
                            assignment.witness(component.W(3), row) = diff != 0 ? 1 / diff : 0;
                        } else {
                            row++;
                            assignment.witness(component.W(0), row) = diff != 0 ? 1 / diff : 0;
                        }
                        break;
                    case comparison_mode::LESS_EQUAL:
                    case comparison_mode::GREATER_EQUAL:
                        break;
                    case comparison_mode::FLAG:
                        BOOST_ASSERT_MSG(false, "FLAG mode is not supported, use comparison_flag component instead.");
                }
                row++;
                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constants(
                const plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_comparison_checked<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = 0;
            }
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_NON_NATIVE_COMPARISON_CHECKED_HPP

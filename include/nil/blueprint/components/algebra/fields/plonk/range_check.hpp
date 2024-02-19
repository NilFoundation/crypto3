//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_RANGE_CHECK_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_RANGE_CHECK_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <utility>
#include <type_traits>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {

            // Constraint that x < 2**bits_amount.
            // Works when bits_amount < modulus_bits.
            // Input: x \in Fp
            // Takes one gate less for bits_amount divisible by chunk_size.
            template<typename ArithmetizationType>
            class range_check;

            // The idea is split x in ConstraintDegree-bit chunks.
            // Then, for each chunk x_i, we constraint that x_i < 2**ConstraintDegree.
            // Thus, we get bits_amount/ConstraintDegree chunks that is proved to be less than 2**ConstraintDegree.
            // We can aggreate them into one value < 2**bits_amount.
            // Layout:
            // W0  | W1   | ... | W14
            //  0  | ...  | ... | ...
            // sum | c_0  | ... | c_13
            // sum | c_14 | ... | c_27
            // ...
            // The last sum = x
            template<typename BlueprintFieldType>
            class range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> :
                public plonk_component<BlueprintFieldType> {

                static std::size_t chunks_per_row_internal(std::size_t witness_amount) {
                    return witness_amount - reserved_columns;
                }

                static std::size_t bits_per_row_internal(std::size_t witness_amount) {
                    return chunks_per_row_internal(witness_amount) * chunk_size;
                }

                static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    // 1 + ceil(bits_amount / bits_per_row)
                    return 1 + (bits_amount + bits_per_row_internal(witness_amount) - 1) /
                                bits_per_row_internal(witness_amount);
                }

                static std::size_t padded_chunks_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return (rows_amount_internal(witness_amount, bits_amount) - 1) *
                            chunks_per_row_internal(witness_amount);
                }

                static std::size_t padding_size_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return padded_chunks_internal(witness_amount, bits_amount) -
                            (bits_amount + chunk_size - 1) / chunk_size;
                }

                static std::size_t padding_bits_internal(std::size_t witness_amount, std::size_t bits_amount) {
                    return padded_chunks_internal(witness_amount, bits_amount) * chunk_size - bits_amount;
                }

                static std::size_t gates_amount_internal(std::size_t bits_amount) {
                    return 1 + (bits_amount % chunk_size == 0 ? 0 : 1);
                }

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t witness_amount;
                    std::size_t bits_amount;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t bits_amount_)
                        : witness_amount(witness_amount_), bits_amount(bits_amount_) {}

                    std::uint32_t gates_amount() const override {
                        return range_check::gates_amount_internal(bits_amount);
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        std::size_t other_witness_amount =
                            dynamic_cast<const gate_manifest_type*>(other)->witness_amount;
                        return
                            (witness_amount < other_witness_amount) ||
                            (witness_amount == other_witness_amount &&
                             bits_amount < dynamic_cast<const gate_manifest_type*>(other)->bits_amount);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t bits_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, bits_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(2, BlueprintFieldType::modulus_bits / chunk_size + 1)),
                        true
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t bits_amount) {
                    return rows_amount_internal(witness_amount, bits_amount);
                }

                /*
                   It's CRITICAL that these three variables remain on top
                   Otherwise initialization goes in wrong order, leading to arbitrary values.
                */
                const std::size_t bits_amount;
                constexpr static const std::size_t chunk_size = 2;
                constexpr static const std::size_t reserved_columns = 1;
                /* Do NOT move the above variables! */

                const std::size_t chunks_per_row = chunks_per_row_internal(this->witness_amount());
                const std::size_t bits_per_row = bits_per_row_internal(this->witness_amount());

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), bits_amount);

                const std::size_t padded_chunks = padded_chunks_internal(this->witness_amount(), bits_amount);
                const std::size_t padding_size = padding_size_internal(this->witness_amount(), bits_amount);
                const std::size_t padding_bits = padding_bits_internal(this->witness_amount(), bits_amount);
                const std::size_t gates_amount = gates_amount_internal(bits_amount);

                struct input_type {
                    var x;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct result_type {
                    result_type(const range_check &component, std::size_t start_row_index) {}

                    std::vector<var> all_vars() const {
                        return {};
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                            typename PublicInputContainerType>
                    range_check(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input,
                                std::size_t bits_amount_):
                        component_type(witness, constant, public_input, get_manifest()),
                        bits_amount(bits_amount_) {}

                range_check(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t bits_amount_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        bits_amount(bits_amount_) {}
            };


            template<typename BlueprintFieldType>
            using plonk_range_check =
                range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_range_check<BlueprintFieldType>::result_type
            generate_circuit(
                const plonk_range_check<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::vector<std::size_t> selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index[0], start_row_index + 1,
                                           start_row_index + component.rows_amount - 1);
                if ((component.bits_amount % component.chunk_size) != 0) {
                    if (selector_index.size() != 2) {
                        std::cerr << "Internal error: range_check component returned the wrong selector amount."
                                  << std::endl;
                        std::abort();
                    }
                    assignment.enable_selector(selector_index[1], start_row_index + 1);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constants(component, assignment, instance_input, start_row_index);

                return typename plonk_range_check<BlueprintFieldType>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_range_check<BlueprintFieldType>::result_type
            generate_assignments(
                const plonk_range_check<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_range_check<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using chunk_type = std::uint8_t;
                BOOST_ASSERT(component.chunk_size <= 8);

                value_type x = var_value(assignment, instance_input.x);

                integral_type x_integral = integral_type(x.data);

                std::vector<bool> bits(component.bits_amount + component.padding_bits);
                std::fill(bits.begin(), bits.end(), false);
                {
                    nil::marshalling::status_type status;
                    std::array<bool, BlueprintFieldType::modulus_bits> bytes_all =
                        nil::marshalling::pack<nil::marshalling::option::big_endian>(x_integral, status);
                    std::copy(bytes_all.end() - component.bits_amount, bytes_all.end(),
                                bits.begin() + component.padding_bits);
                    assert(status == nil::marshalling::status_type::success);
                }

                BOOST_ASSERT(component.chunk_size <= 8);

                std::vector<chunk_type> chunks(component.padded_chunks);
                for (std::size_t i = 0; i < component.padded_chunks; i++) {
                    chunk_type chunk_value = 0;
                    for (std::size_t j = 0; j < component.chunk_size; j++) {
                        chunk_value <<= 1;
                        chunk_value |= bits[i * component.chunk_size + j];
                    }
                    chunks[i] = chunk_value;
                }

                assignment.witness(component.W(0), row) = 0;
                row++;

                value_type sum = 0;

                for (std::size_t i = 0; i < component.rows_amount - 1; i++) {
                    for (std::size_t j = 0; j < component.chunks_per_row; j++) {
                        assignment.witness(component.W(0 + component.reserved_columns + j), row) =
                            chunks[i * component.chunks_per_row + j];
                        sum *= (1 << component.chunk_size);
                        sum += chunks[i * component.chunks_per_row + j];
                    }
                    assignment.witness(component.W(0), row) = sum;
                    row++;
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_range_check<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType>::input_type
                    &instance_input) {

                using var = typename plonk_range_check<BlueprintFieldType>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                typename BlueprintFieldType::value_type base_two = 2;

                std::vector<constraint_type> constraints;

                auto generate_chunk_size_constraint = [](var v, std::size_t size) {
                    constraint_type constraint = v;
                    for (std::size_t i = 1; i < (std::size_t(1) << size); i++) {
                        constraint = constraint * (v - i);
                    }
                    return constraint;
                };

                // assert chunk size
                for (std::size_t i = 0; i < component.chunks_per_row; i++) {
                    constraint_type chunk_range_constraint = generate_chunk_size_constraint(
                        var(component.W(0 + component.reserved_columns + i), 0, true), component.chunk_size);

                    constraints.push_back(chunk_range_constraint);
                }
                // assert sum
                constraint_type sum_constraint = var(component.W(0 + component.reserved_columns), 0, true);
                for (std::size_t i = 1; i < component.chunks_per_row; i++) {
                    sum_constraint =
                        base_two.pow(component.chunk_size) * sum_constraint +
                        var(component.W(0 + component.reserved_columns + i), 0, true);
                }
                sum_constraint = sum_constraint +
                                    base_two.pow(component.chunk_size * component.chunks_per_row) *
                                                var(component.W(0), -1, true) -
                                    var(component.W(0), 0, true);
                constraints.push_back(sum_constraint);

                std::size_t selector_index_1 = bp.add_gate(constraints);
                if (component.bits_amount % component.chunk_size == 0) return {selector_index_1};
                // If bits_amount is not divisible by chunk size, the first chunk should be constrained to be
                // less than 2^{bits_amount % chunk_size}
                constraint_type first_chunk_range_constraint = generate_chunk_size_constraint(
                    var(component.W(0 + component.reserved_columns + component.padding_size), 0, true),
                    component.bits_amount % component.chunk_size);

                std::size_t selector_index_2 = bp.add_gate(first_chunk_range_constraint);
                return {selector_index_1, selector_index_2};
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_range_check<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_range_check<BlueprintFieldType>::var;

                var zero(0, start_row_index, false, var::column_type::constant);
                bp.add_copy_constraint({zero, var(component.W(0), start_row_index, false)});

                for (std::size_t i = 1; i <= component.padding_size; i++) {
                    bp.add_copy_constraint({zero, var(component.W(i), start_row_index + 1, false)});
                }

                bp.add_copy_constraint({instance_input.x,
                                        var(component.W(0), start_row_index + component.rows_amount - 1, false)});
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constants(
                const plonk_range_check<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_range_check<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = 0;
            }
        }   // namespace components
    }       // namespace blueprint
}   // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_RANGE_CHECK_HPP
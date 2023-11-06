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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_ARRAY_SWAP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_ARRAY_SWAP_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Input: t, array <a1, b1, a2, b2, ..., an, bn>
            // Output: <a1,b1,a2,b2,....,an,bn> if t == 0, <b1,a1,b2,a2,....,bn,an> if t == 1
            // Does NOT check that t is really a bit.
            // Configuration is suboptimal: we do rows of the form
            // t, a1, b1, o11, o12, a2, b2, o21, o22, ...
            // We could reuse t among multiple different rows for a better configuration, but that would be
            // more complex than what we can quickly implement now.
            template<typename ArithmetizationType, typename FieldType>
            class fri_array_swap;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class fri_array_swap<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t half_array_size;

                class gate_manifest_type : public component_gate_manifest {
                private:
                    std::size_t witness_amount;
                    std::size_t half_array_size;

                public:
                    gate_manifest_type(std::size_t witness_amount_, std::size_t half_array_size_) :
                        witness_amount((witness_amount_ - 1) / 4), half_array_size(half_array_size_) {};

                    bool operator<(gate_manifest_type const& other) const {
                        return witness_amount < other.witness_amount ||
                               (witness_amount == other.witness_amount && half_array_size < other.half_array_size);
                    }

                    std::uint32_t gates_amount() const override {
                        return fri_array_swap::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t half_array_size) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, half_array_size));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // TODO: make the manifest depend on half_array_size
                        // this requires the manifest rework
                        std::shared_ptr<manifest_param>(new manifest_range_param(5, 100500, 4)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t half_array_size) {
                    return (2 * half_array_size + (witness_amount - 1) / 4 - 1) / ((witness_amount - 1) / 4);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, half_array_size);

                struct input_type {
                    var t; // swap control bit
	                std::vector<var> arr; // the array with elements to swap

                    std::vector<var> all_vars() const {
                        std::vector<var> result;
                        result.reserve(1 + arr.size());
                        result.push_back(t);
                        result.insert(result.end(), arr.begin(), arr.end());
                        return result;
                    }
                };

                struct result_type {
		            std::vector<var> output; // the array with possibly swapped elements

                    result_type(const fri_array_swap &component, std::size_t start_row_index) {
                        const std::size_t array_size = 2 * component.half_array_size;
                        const std::size_t witness_amount = component.witness_amount();
                        const std::size_t rows_amount = component.rows_amount;

                        output.reserve(array_size);
                        for (std::size_t row = 0, pair_index = 0; row < rows_amount; row++) {
                            for (std::size_t offset = 1; offset < witness_amount - 1 && pair_index < array_size;
                                 offset += 4, pair_index += 2) {
                                output.emplace_back(
                                    var(component.W(offset + 2), start_row_index + row, false));
                                output.emplace_back(
                                    var(component.W(offset + 3), start_row_index + row, false));
                            }
                        }
                    }

                    std::vector<var> all_vars() const {
                        return output;
                    }
                };

                template<typename ContainerType>
                explicit fri_array_swap(ContainerType witness, std::size_t half_array_size_) :
                    component_type(witness, {}, {}, get_manifest()),
                    half_array_size(half_array_size_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fri_array_swap(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, std::size_t half_array_size_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    half_array_size(half_array_size_) {};

                fri_array_swap(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t half_array_size_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    half_array_size(half_array_size_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fri_array_swap =
                fri_array_swap<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;

                BOOST_ASSERT(2 * component.half_array_size == instance_input.arr.size());
                const std::size_t array_size = instance_input.arr.size();
                const std::size_t witness_amount = component.witness_amount();
                const std::size_t rows_amount = component.rows_amount;
                value_type t = var_value(assignment, instance_input.t);

                for (std::size_t row = 0, pair_index = 0; row < rows_amount; row++) {
                    assignment.witness(component.W(0), start_row_index + row) =
                        var_value(assignment, instance_input.t);
                    for (std::size_t offset = 1; offset < witness_amount - 1; offset += 4, pair_index += 2) {
                        if (pair_index < array_size) {
                            value_type a_val = var_value(assignment, instance_input.arr[pair_index]);
                            value_type b_val = var_value(assignment, instance_input.arr[pair_index + 1]);
                            assignment.witness(component.W(offset), start_row_index + row) = a_val;
                            assignment.witness(component.W(offset + 1), start_row_index + row) = b_val;
                            if (t == 0) {
                                assignment.witness(component.W(offset + 2), start_row_index + row) = a_val;
                                assignment.witness(component.W(offset + 3), start_row_index + row) = b_val;
                            } else {
                                assignment.witness(component.W(offset + 2), start_row_index + row) = b_val;
                                assignment.witness(component.W(offset + 3), start_row_index + row) = a_val;
                            }
                        } else {
                            assignment.witness(component.W(offset), start_row_index + row) = 0;
                            assignment.witness(component.W(offset + 1), start_row_index + row) = 0;
                            assignment.witness(component.W(offset + 2), start_row_index + row) = 0;
                            assignment.witness(component.W(offset + 3), start_row_index + row) = 0;
                        }
                    }
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using component_type = plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                const std::size_t four_amount = (component.witness_amount() - 1) / 4;
                BOOST_ASSERT(2 * component.half_array_size == instance_input.arr.size());
                const std::size_t array_size = instance_input.arr.size();

                std::vector<constraint_type> constraints;
                constraints.reserve(component.half_array_size);
                var t = var(component.W(0), 0, true);
                const std::size_t witness_amount = component.witness_amount();
                for (std::size_t offset = 1; offset < witness_amount - 1; offset += 4) {
                    var input_a_var = var(component.W(offset), 0, true),
                        output_a_var = var(component.W(offset + 2), 0, true),
                        input_b_var = var(component.W(offset + 1), 0, true),
                        output_b_var = var(component.W(offset + 3), 0, true);

                    constraints.emplace_back(output_a_var - input_a_var * (1 - t) - input_b_var * t);
                    constraints.emplace_back(output_b_var - input_b_var * (1 - t) - input_a_var * t);
                }

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;

                BOOST_ASSERT(2 * component.half_array_size == instance_input.arr.size());
                const std::size_t array_size = instance_input.arr.size();
                const std::size_t witness_amount = component.witness_amount();
                const std::size_t rows_amount = component.rows_amount;

                for (std::size_t row = 0, pair_index = 0; row < rows_amount; row++) {
                    bp.add_copy_constraint(
                        {instance_input.t, var(component.W(0), start_row_index + row, false)});
                    for (std::size_t offset = 1; offset < witness_amount - 1 && pair_index < array_size;
                         offset += 4, pair_index += 2) {
                        bp.add_copy_constraint(
                            {instance_input.arr[pair_index],
                                var(component.W(offset), start_row_index + row, false)});
                        bp.add_copy_constraint(
                            {instance_input.arr[pair_index + 1],
                                var(component.W(offset + 1), start_row_index + row, false)});
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_fri_array_swap<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(
                    selector_index, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FRI_ARRAY_SWAP_HPP
//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <iostream>
#include <iterator>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, typename BlueprintFieldType>
            class pow_factor;

            // Efficiently calculating a polynomial of a single variable
            // layout is made of repeated blocks like this (shown for witness_amount = 18)
            // --------------------------------------------------------------------------------
            // |theta|c_14|c_13|c_12|c_11|c_10|c_9|c_8|c_7|r_0|c_6|c_5|c_4|c_3|c_2|c_1|c_0|r_1|
            // --------------------------------------------------------------------------------
            // Calculating polynomials of 7-th degree at a time
            // Carrying of the results between rows is done via copy constrainting into the first variable (after theta)
            // of the next row; the amount of coefficients is padded at the beginning with zeroes to the
            template<typename BlueprintFieldType>
            class pow_factor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                             BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {
            public:

                static std::size_t row_capacity(std::size_t witness_amount) {
                    return witness_amount == 10 ? 8 : 8 + (witness_amount - 10) / 8 * 7;
                }

                static std::size_t total_rows_amount(
                        std::size_t witness_amount, std::size_t curr_vars, std::size_t rows = 0) {
                    const std::size_t row_capacity = pow_factor::row_capacity(witness_amount);
                    if (curr_vars <= row_capacity) {
                        return rows + 1;
                    }
                    rows += curr_vars / row_capacity;
                    curr_vars = curr_vars % row_capacity + curr_vars / row_capacity;
                    return total_rows_amount(witness_amount, curr_vars, rows);
                }

                static std::size_t calculate_padding(std::size_t witness_amount, std::size_t power) {
                    const std::size_t row_capacity = pow_factor::row_capacity(witness_amount);
                    const std::size_t total_rows = total_rows_amount(witness_amount, power + 1);
                    const std::size_t total_capacity = total_rows * row_capacity;
                    const std::size_t bonus_vars = total_rows - 1;
                    return total_capacity - bonus_vars - (power + 1);
                }

                static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t power) {
                    return total_rows_amount(witness_amount, power + 1);
                }

                std::size_t power;

                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                private:
                    std::size_t witness_amount;

                public:
                    gate_manifest_type(std::size_t witness_amount_) :
                        witness_amount((witness_amount_ - 10) / 8){};

                    bool operator<(gate_manifest_type const& other) const {
                        return witness_amount < other.witness_amount ||
                               (witness_amount == other.witness_amount);
                    }

                    std::uint32_t gates_amount() const override {
                        return pow_factor::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t power) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest(
                    std::size_t power) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(10, 10 + power / 6 + 1, 8)),
                        true
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t power) {
                    return rows_amount_internal(witness_amount, power);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), power);
                const std::string component_name = "fri array swap component";

                struct input_type {
                    var theta;
	                std::vector<var> coefficients; // coefficients; highest power first

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.reserve(1 + coefficients.size());
                        result.push_back(theta);
                        result.insert(result.end(), coefficients.begin(), coefficients.end());
                        return result;
                    }
                };

                struct result_type {
		            var output;

                    result_type(const pow_factor &component, std::size_t start_row_index) {
                        const std::size_t end_row_index = start_row_index + component.rows_amount - 1;
                        output = var(component.W(component.witness_amount() - 1), end_row_index, false);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit pow_factor(ContainerType witness, std::size_t power_) :
                    component_type(witness, {}, {}, get_manifest(power_)),
                    power(power_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                pow_factor(WitnessContainerType witness, ConstantContainerType constant,
                          PublicInputContainerType public_input, std::size_t power_) :
                    component_type(witness, constant, public_input, get_manifest(power_)),
                    power(power_) {};

                pow_factor(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t power_) :
                    component_type(witnesses, constants, public_inputs, get_manifest(power_)),
                    power(power_) {};

                inline std::vector<var> pad_input(const std::vector<var> &input,
                                                  std::size_t start_row_index, std::size_t padding) const {
                    std::vector<var> padded_arr;
                    padded_arr.reserve(input.size() + padding);
                    var zero = var(this->C(0), start_row_index, false, var::column_type::constant);
                    for (std::size_t i = 0; i < padding; i++) {
                        padded_arr.push_back(zero);
                    }
                    padded_arr.insert(padded_arr.end(), input.begin(), input.end());
                    BOOST_ASSERT(padded_arr.size() == input.size() + padding);
                    return padded_arr;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_pow_factor =
                pow_factor<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_pow_factor<BlueprintFieldType>::result_type generate_assignments(
                const plonk_pow_factor<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_pow_factor<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_pow_factor<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using var = typename component_type::var;

                BOOST_ASSERT(component.power + 1 == instance_input.coefficients.size());
                // copy this here because we use the zero constant value to pad the input
                generate_assignments_constant(component, assignment, start_row_index);
                const std::size_t padding = component_type::calculate_padding(component.witness_amount(), component.power);
                std::vector<var> padded_arr = component.pad_input(instance_input.coefficients, start_row_index, padding);
                std::size_t row = start_row_index;
                std::size_t var_index = 0;
                value_type poly_value = var_value(assignment, padded_arr[var_index++]);
                value_type theta = var_value(assignment, instance_input.theta);
                while (var_index < padded_arr.size()) {
                    assignment.witness(component.W(0), row) = theta;
                    assignment.witness(component.W(1), row) = poly_value;
                    for (std::size_t i = 1; i < component.witness_amount() - 1; i += 8) {
                        for (std::size_t j = i + 1; j < i + 8; j++) {
                            value_type coeff_value = var_value(assignment, padded_arr[var_index++]);
                            assignment.witness(component.W(j), row) = coeff_value;
                            poly_value = poly_value * theta + coeff_value;
                        }
                        assignment.witness(component.W(i + 8), row) = poly_value;
                    }
                    row++;
                }
                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_pow_factor<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_pow_factor<BlueprintFieldType>::input_type
                    &instance_input) {

                using component_type = plonk_pow_factor<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::vector<constraint_type> constraints;
                var theta = var(component.W(0), 0);
                for (std::size_t start_index = 1; start_index < component.witness_amount() - 1; start_index += 8) {
                    std::array<var, 8> coefficients;
                    for (std::size_t i = start_index; i < start_index + 8; i++) {
                        coefficients[i - start_index] = var(component.W(i), 0, true, var::column_type::witness);
                    }
                    constraint_type new_constraint = coefficients[0];
                    for (std::size_t i = 1; i < 8; i++) {
                        new_constraint = new_constraint * theta + coefficients[i];
                    }
                    new_constraint -= var(component.W(start_index + 8), 0, true, var::column_type::witness);
                    constraints.push_back(new_constraint);
                }

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_pow_factor<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_pow_factor<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_pow_factor<BlueprintFieldType>;
                using var = typename component_type::var;

                const std::size_t padding = component_type::calculate_padding(component.witness_amount(), component.power);
                std::vector<var> padded_arr = component.pad_input(instance_input.coefficients, start_row_index, padding);
                var zero = var(component.C(0), start_row_index, false, var::column_type::constant);
                std::size_t slot_index = 1;
                std::size_t var_index = 0;
                std::size_t row = start_row_index;
                bp.add_copy_constraint(
                    {instance_input.theta,
                     var(component.W(0), start_row_index, false, var::column_type::witness)});
                while (var_index < padded_arr.size()) {
                    if ((slot_index - 9) % 8 == 0 && slot_index >= 9) {
                        slot_index++;
                    }
                    if (slot_index >= component.witness_amount() - 1) {
                        slot_index = 2;
                        if (row + 1 < start_row_index + component.rows_amount) {
                            bp.add_copy_constraint(
                                {var(component.W(component.witness_amount() - 1), row, false, var::column_type::witness),
                                 var(component.W(1), row + 1, false, var::column_type::witness)});
                            bp.add_copy_constraint(
                                {instance_input.theta,
                                 var(component.W(0), row + 1, false, var::column_type::witness)});
                        }
                        row++;
                    }
                    if (var_index < padding) {
                        bp.add_copy_constraint(
                            {zero,
                             var(component.W(slot_index), row, false, var::column_type::witness)});
                    } else {
                        bp.add_copy_constraint(
                            {padded_arr[var_index],
                             var(component.W(slot_index), row, false, var::column_type::witness)});
                    }
                    slot_index++;
                    var_index++;
                }
                row++;
                BOOST_ASSERT(row == start_row_index + component.rows_amount);
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const plonk_pow_factor<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = BlueprintFieldType::value_type::zero();
            }

            template<typename BlueprintFieldType>
            typename plonk_pow_factor<BlueprintFieldType>::result_type generate_circuit(
                const plonk_pow_factor<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_pow_factor<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_pow_factor<BlueprintFieldType>;

                BOOST_ASSERT(component.power + 1 == instance_input.coefficients.size());

                generate_assignments_constant(component, assignment, start_row_index);
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(
                    selector_index, start_row_index, start_row_index + component.rows_amount - 1);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }   // namespace components
    }       // namespace blueprint
}   // namespace nil
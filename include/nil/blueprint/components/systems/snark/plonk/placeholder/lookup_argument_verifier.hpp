//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the LOOKUP_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/f1_loop.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/f3_loop.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/gate_component.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
            class lookup_verifier;

            template<typename BlueprintFieldType>
            class lookup_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

                constexpr static const std::uint32_t ConstantsAmount = 1;

                constexpr static const std::size_t
                    rows_amount_internal(std::size_t witness_amount, const std::size_t lookup_gates_size,
                                         const std::vector<std::size_t> &lookup_gate_constraints_sizes,
                                         const std::vector<std::size_t> &lookup_gate_constraints_lookup_input_sizes,
                                         const std::size_t lookup_tables_size,
                                         const std::vector<std::size_t> &lookup_table_lookup_options_sizes,
                                         const std::vector<std::size_t> &lookup_table_columns_numbers) {

                    std::size_t row = 2;

                    std::size_t lu_value_size = 0;
                    for (std::size_t i = 0; i < lookup_tables_size; i++) {
                        for (std::size_t j = 0; j < lookup_table_lookup_options_sizes[i]; j++) {
                            row +=
                                2 * gate_component::get_rows_amount(witness_amount, 0, lookup_table_columns_numbers[i]);
                            row += 2 * mul::get_rows_amount(witness_amount, 0);
                            lu_value_size++;
                        }
                    }

                    std::size_t lu_input_size = 0;
                    for (std::size_t g_id = 0; g_id < lookup_gates_size; g_id++) {
                        for (std::size_t c_id = 0; c_id < lookup_gate_constraints_sizes[g_id]; c_id++) {
                            std::size_t lookup_input_size = lookup_gate_constraints_lookup_input_sizes[lu_input_size++];
                            row += gate_component::get_rows_amount(witness_amount, 0, lookup_input_size);
                        }
                    }

                    row += f1_loop::get_rows_amount(witness_amount, 0, lu_input_size);
                    row += f1_loop::get_rows_amount(witness_amount, 0, lu_value_size);
                    row += f1_loop::get_rows_amount(witness_amount, 0, lu_input_size + lu_value_size);
                    row += 2 * mul::get_rows_amount(witness_amount, 0);
                    row += f3_loop::get_rows_amount(witness_amount, 0, lu_input_size + lu_value_size - 1);
                    row += 4 / witness_amount + 1;
                    row += 5 / witness_amount + 1;
                    return row;
                }

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using f1_loop = detail::f1_loop<ArithmetizationType>;
                using f3_loop = detail::f3_loop<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                constexpr static std::size_t get_rows_amount(
                    std::size_t witness_amount, std::size_t lookup_column_amount, std::size_t lookup_gates_size,
                    std::vector<std::size_t> &lookup_gate_constraints_sizes,
                    std::vector<std::size_t> &lookup_gate_constraints_lookup_input_sizes,
                    std::size_t lookup_tables_size, std::vector<std::size_t> &lookup_table_lookup_options_sizes,
                    std::vector<std::size_t> &lookup_table_columns_numbers) {

                    return rows_amount_internal(witness_amount, lookup_gates_size, lookup_gate_constraints_sizes,
                                                lookup_gate_constraints_lookup_input_sizes, lookup_tables_size,
                                                lookup_table_lookup_options_sizes, lookup_table_columns_numbers);
                }

                const std::size_t lookup_gates_size;
                const std::size_t lookup_tables_size;
                const std::vector<std::size_t> lookup_table_lookup_options_sizes;
                const std::vector<std::size_t> lookup_table_columns_numbers;
                const std::vector<std::size_t> lookup_gate_constraints_sizes;
                const std::vector<std::size_t> lookup_gate_constraints_lookup_input_sizes;
                const std::size_t rows_amount =
                    rows_amount_internal(this->witness_amount(), lookup_gates_size, lookup_gate_constraints_sizes,
                                         lookup_gate_constraints_lookup_input_sizes, lookup_tables_size,
                                         lookup_table_lookup_options_sizes, lookup_table_columns_numbers);

                constexpr static std::size_t gates_amount = 3;
                const std::string component_name = "lookup argument verifier component";

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 3;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount, std::size_t lookup_column_amount, std::size_t lookup_gates_size,
                    std::vector<std::size_t> &lookup_gate_constraints_sizes,
                    std::vector<std::size_t> &lookup_gate_constraints_lookup_input_sizes,
                    std::size_t lookup_tables_size, std::vector<std::size_t> &lookup_table_lookup_options_sizes,
                    std::vector<std::size_t> &lookup_table_columns_numbers) {

                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                            .merge_with(mul::get_gate_manifest(witness_amount, lookup_column_amount))
                            .merge_with(f1_loop::get_gate_manifest(witness_amount, lookup_column_amount, 1))
                            .merge_with(f3_loop::get_gate_manifest(witness_amount, lookup_column_amount, 1))
                            .merge_with(gate_component::get_gate_manifest(witness_amount, lookup_column_amount, 1));

                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(4, 15)), false)
                            .merge_with(mul::get_manifest())
                            .merge_with(f1_loop::get_manifest())
                            .merge_with(f3_loop::get_manifest())
                            .merge_with(gate_component::get_manifest());
                    return manifest;
                }

                struct input_type {
                    var theta;
                    var beta;
                    var gamma;
                    std::vector<var> alphas;
                    std::array<var, 2> V_L_values;
                    std::array<var, 2> q_last;
                    std::array<var, 2> q_blind;
                    var L0;

                    std::vector<var> lookup_gate_selectors;
                    std::vector<var> lookup_gate_constraints_table_ids;
                    std::vector<var> lookup_gate_constraints_lookup_inputs;

                    std::vector<var> lookup_table_selectors;
                    std::vector<var> lookup_table_lookup_options;

                    std::vector<var> shifted_lookup_table_selectors;
                    std::vector<var> shifted_lookup_table_lookup_options;

                    std::vector<var> sorted;

                    std::vector<std::reference_wrapper<var>> all_vars() {

                        std::vector<std::reference_wrapper<var>> vars;
                        vars.push_back(theta);
                        vars.push_back(beta);
                        vars.push_back(gamma);
                        vars.insert(vars.end(), alphas.begin(), alphas.end());
                        vars.insert(vars.end(), V_L_values.begin(), V_L_values.end());
                        vars.insert(vars.end(), q_last.begin(), q_last.end());
                        vars.insert(vars.end(), q_blind.begin(), q_blind.end());
                        vars.push_back(L0);
                        vars.insert(vars.end(), lookup_gate_selectors.begin(), lookup_gate_selectors.end());
                        vars.insert(vars.end(), lookup_gate_constraints_table_ids.begin(),
                                    lookup_gate_constraints_table_ids.end());
                        vars.insert(vars.end(), lookup_gate_constraints_lookup_inputs.begin(),
                                    lookup_gate_constraints_lookup_inputs.end());
                        vars.insert(vars.end(), lookup_table_selectors.begin(), lookup_table_selectors.end());
                        vars.insert(vars.end(), lookup_table_lookup_options.begin(), lookup_table_lookup_options.end());
                        vars.insert(vars.end(), shifted_lookup_table_selectors.begin(),
                                    shifted_lookup_table_selectors.end());
                        vars.insert(vars.end(), shifted_lookup_table_lookup_options.begin(),
                                    shifted_lookup_table_lookup_options.end());
                        vars.insert(vars.end(), sorted.begin(), sorted.end());

                        return vars;
                    }
                };

                struct result_type {
                    std::array<var, 4> output;

                    result_type(const lookup_verifier &component, std::uint32_t start_row_index) {
                        std::size_t w = component.witness_amount();
                        std::size_t offset = 4 / w + 5 / w + 2;
                        output = {
                            var(component.W(2 % w), start_row_index + component.rows_amount - offset + 2 / w, false),
                            var(component.W(4 % w), start_row_index + component.rows_amount - offset + 4 / w, false),
                            var(component.W(5 % w), start_row_index + component.rows_amount - 1, false),
                            var(component.W(2), start_row_index + component.rows_amount - offset - 1, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output[0], output[1], output[2], output[3]};
                    }
                };

                template<typename ContainerType>
                lookup_verifier(ContainerType witness, std::size_t lookup_gates_size_,
                                std::vector<std::size_t> &lookup_gate_constraints_sizes_,
                                std::vector<std::size_t> &lookup_gate_constraints_lookup_input_sizes_,
                                std::size_t lookup_tables_size_,
                                std::vector<std::size_t> &lookup_table_lookup_options_sizes_,
                                std::vector<std::size_t> &lookup_table_columns_numbers_) :
                    component_type(witness, {}, {}, get_manifest()),
                    lookup_gates_size(lookup_gates_size_),
                    lookup_tables_size(lookup_tables_size_),
                    lookup_table_lookup_options_sizes(lookup_table_lookup_options_sizes_),
                    lookup_table_columns_numbers(lookup_table_columns_numbers_),
                    lookup_gate_constraints_sizes(lookup_gate_constraints_sizes_),
                    lookup_gate_constraints_lookup_input_sizes(lookup_gate_constraints_lookup_input_sizes_) {}

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                lookup_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input, std::size_t lookup_gates_size_,
                                std::vector<std::size_t> &lookup_gate_constraints_sizes_,
                                std::vector<std::size_t> &lookup_gate_constraints_lookup_input_sizes_,
                                std::size_t lookup_tables_size_,
                                std::vector<std::size_t> &lookup_table_lookup_options_sizes_,
                                std::vector<std::size_t> &lookup_table_columns_numbers_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    lookup_gates_size(lookup_gates_size_),
                    lookup_tables_size(lookup_tables_size_),
                    lookup_table_lookup_options_sizes(lookup_table_lookup_options_sizes_),
                    lookup_table_columns_numbers(lookup_table_columns_numbers_),
                    lookup_gate_constraints_sizes(lookup_gate_constraints_sizes_),
                    lookup_gate_constraints_lookup_input_sizes(lookup_gate_constraints_lookup_input_sizes_) {}

                lookup_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t lookup_gates_size_, std::vector<std::size_t> &lookup_gate_constraints_sizes_,
                    std::vector<std::size_t> &lookup_gate_constraints_lookup_input_sizes_,
                    std::size_t lookup_tables_size_, std::vector<std::size_t> &lookup_table_lookup_options_sizes_,
                    std::vector<std::size_t> &lookup_table_columns_numbers_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    lookup_gates_size(lookup_gates_size_),
                    lookup_tables_size(lookup_tables_size_),
                    lookup_table_lookup_options_sizes(lookup_table_lookup_options_sizes_),
                    lookup_table_columns_numbers(lookup_table_columns_numbers_),
                    lookup_gate_constraints_sizes(lookup_gate_constraints_sizes_),
                    lookup_gate_constraints_lookup_input_sizes(lookup_gate_constraints_lookup_input_sizes_) {}
            };

            template<typename BlueprintFieldType>
            using plonk_lookup_verifier =
                lookup_verifier<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const plonk_lookup_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                typename BlueprintFieldType::value_type one = BlueprintFieldType::value_type::one();
                for (std::size_t i = 0; i < instance_input.lookup_table_selectors.size(); i++) {
                    assignment.constant(component.C(0), start_row_index + i) = one + i;
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_lookup_verifier<BlueprintFieldType>::result_type generate_assignments(
                const plonk_lookup_verifier<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                using var = typename plonk_lookup_verifier<BlueprintFieldType>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                    ArithmetizationType;

                using f1_loop = detail::f1_loop<ArithmetizationType>;
                using f3_loop = detail::f3_loop<ArithmetizationType>;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                std::vector<std::uint32_t> witnesses;
                for (std::uint32_t i = 0; i < witness_amount; i++) {
                    witnesses.push_back(component.W(i));
                }

                typename BlueprintFieldType::value_type one = BlueprintFieldType::value_type::one();
                typename BlueprintFieldType::value_type q_last = var_value(assignment, instance_input.q_last[0]);
                typename BlueprintFieldType::value_type q_last_shifted =
                    var_value(assignment, instance_input.q_last[1]);
                typename BlueprintFieldType::value_type q_blind = var_value(assignment, instance_input.q_blind[0]);
                typename BlueprintFieldType::value_type q_blind_shifted =
                    var_value(assignment, instance_input.q_blind[1]);
                typename BlueprintFieldType::value_type L0 = var_value(assignment, instance_input.L0);
                typename BlueprintFieldType::value_type V_L = var_value(assignment, instance_input.V_L_values[0]);
                typename BlueprintFieldType::value_type V_L_shifted =
                    var_value(assignment, instance_input.V_L_values[1]);

                typename BlueprintFieldType::value_type F0 = (one - V_L) * L0;
                typename BlueprintFieldType::value_type F1 = q_last * (V_L * V_L - V_L);

                std::vector<typename BlueprintFieldType::value_type> assignments;

                typename BlueprintFieldType::value_type mask_value = (one - (q_last + q_blind));
                typename BlueprintFieldType::value_type shifted_mask_value = (one - (q_last_shifted + q_blind_shifted));

                assignment.witness(component.W(0), row) = q_last;
                assignment.witness(component.W(1), row) = q_blind;
                assignment.witness(component.W(2), row) = mask_value;
                assignment.witness(component.W(0), row + 1) = q_last_shifted;
                assignment.witness(component.W(1), row + 1) = q_blind_shifted;
                assignment.witness(component.W(2), row + 1) = shifted_mask_value;

                var var_mask = var(component.W(2), row, false);
                var var_shifted_mask = var(component.W(2), row + 1, false);

                row += 2;

                std::vector<var> lookup_values;
                std::vector<var> shifted_lookup_values;

                std::size_t start_pos = 0, offset = 0;
                std::size_t num_tables = instance_input.lookup_table_selectors.size();
                assert(num_tables == component.lookup_tables_size);
                for (std::size_t i = 0; i < num_tables; i++) {
                    var selector = instance_input.lookup_table_selectors[i];
                    var shifted_selector = instance_input.shifted_lookup_table_selectors[i];
                    var t_id_inc = var(component.C(0), start_row_index + i, false, var::column_type::constant);

                    for (std::size_t j = 0; j < component.lookup_table_lookup_options_sizes[i]; j++) {
                        offset = component.lookup_table_columns_numbers[i];
                        std::vector<var> gate_constraints;
                        gate_constraints.push_back(t_id_inc);
                        gate_constraints.insert(gate_constraints.end(),
                                                instance_input.lookup_table_lookup_options.begin() + start_pos,
                                                instance_input.lookup_table_lookup_options.begin() + start_pos +
                                                    offset);

                        gate_component gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                                      std::array<std::uint32_t, 1>(), offset);

                        typename gate_component::input_type gate_input = {instance_input.theta, gate_constraints,
                                                                          selector};

                        typename gate_component::result_type gate_i_result =
                            generate_assignments(gate_instance, assignment, gate_input, row);

                        row += gate_instance.rows_amount;

                        mul mul_instance =
                            mul(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>());

                        typename mul::input_type mul_input = {gate_i_result.output, var_mask};
                        typename mul::result_type mul_result =
                            generate_assignments(mul_instance, assignment, mul_input, row);
                        row += mul_instance.rows_amount;
                        lookup_values.push_back(mul_result.output);

                        gate_constraints.clear();
                        gate_constraints.push_back(t_id_inc);
                        gate_constraints.insert(gate_constraints.end(),
                                                instance_input.shifted_lookup_table_lookup_options.begin() + start_pos,
                                                instance_input.shifted_lookup_table_lookup_options.begin() + start_pos +
                                                    offset);

                        // gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                        //                                std::array<std::uint32_t, 1>(), offset);
                        gate_input = {instance_input.theta, gate_constraints, shifted_selector};
                        gate_i_result = generate_assignments(gate_instance, assignment, gate_input, row);
                        row += gate_instance.rows_amount;

                        mul_input = {gate_i_result.output, var_shifted_mask};
                        mul_result = generate_assignments(mul_instance, assignment, mul_input, row);
                        row += mul_instance.rows_amount;
                        shifted_lookup_values.push_back(mul_result.output);

                        start_pos += offset;
                    }
                }
                assert(lookup_values.size() == shifted_lookup_values.size());

                std::vector<var> lookup_input;
                std::size_t start = 0, lookup_input_size = 0, ctr = 0;
                std::size_t num_gates = instance_input.lookup_gate_selectors.size();
                assert(num_gates == component.lookup_gates_size);
                for (std::size_t g_id = 0; g_id < num_gates; g_id++) {

                    var selector = instance_input.lookup_gate_selectors[g_id];
                    for (std::size_t c_id = 0; c_id < component.lookup_gate_constraints_sizes[g_id]; c_id++) {

                        lookup_input_size = component.lookup_gate_constraints_lookup_input_sizes[ctr];
                        std::vector<var> gate_constraints;
                        gate_constraints.push_back(instance_input.lookup_gate_constraints_table_ids[ctr++]);
                        gate_constraints.insert(gate_constraints.begin() + 1,
                                                instance_input.lookup_gate_constraints_lookup_inputs.begin() + start,
                                                instance_input.lookup_gate_constraints_lookup_inputs.begin() + start +
                                                    lookup_input_size);

                        gate_component gate_instance =
                            gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_input_size);
                        typename gate_component::input_type gate_input = {instance_input.theta, gate_constraints,
                                                                          selector};

                        typename gate_component::result_type gate_i_result =
                            generate_assignments(gate_instance, assignment, gate_input, row);

                        lookup_input.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;
                        start += lookup_input_size;
                    }
                }

                std::vector<var> s0, s1, s2;
                std::size_t k = (instance_input.sorted.size() + 1) / 3;
                for (std::size_t i = 0; i < k; i++) {
                    s0.push_back(instance_input.sorted[i]);
                    s1.push_back(instance_input.sorted[k + i]);
                    if (i >= 1) {
                        s2.push_back(instance_input.sorted[2 * k + i - 1]);
                    }
                }

                assert(s0.size() == s1.size());

                f1_loop h_loop =
                    f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), s0.size());
                typename f1_loop::input_type h_loop_input = {instance_input.beta, instance_input.gamma, s0, s1};

                typename f1_loop::result_type h_loop_result =
                    generate_assignments(h_loop, assignment, h_loop_input, row);

                typename BlueprintFieldType::value_type h = var_value(assignment, h_loop_result.output);
                row += h_loop.rows_amount;

                f1_loop g_loop_1 = f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_input.size());

                typename f1_loop::input_type g_loop_input = {instance_input.beta, instance_input.gamma, lookup_input,
                                                             lookup_input};

                typename f1_loop::result_type g_loop_result =
                    generate_assignments(g_loop_1, assignment, g_loop_input, row);

                typename BlueprintFieldType::value_type g1 = var_value(assignment, g_loop_result.output);
                row += g_loop_1.rows_amount;

                f1_loop g_loop_2 = f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_values.size());

                typename f1_loop::input_type g_loop_input_2 = {instance_input.beta, instance_input.gamma, lookup_values,
                                                               shifted_lookup_values};

                typename f1_loop::result_type g_loop_result_2 =
                    generate_assignments(g_loop_2, assignment, g_loop_input_2, row);

                typename BlueprintFieldType::value_type g2 = var_value(assignment, g_loop_result_2.output);
                row += g_loop_2.rows_amount;

                typename BlueprintFieldType::value_type g = g1 * g2;

                mul mul_instance = mul(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>());
                typename mul::input_type mul_input = {g_loop_result.output, g_loop_result_2.output};
                typename mul::result_type mul_result = generate_assignments(mul_instance, assignment, mul_input, row);
                row += mul_instance.rows_amount;

                typename BlueprintFieldType::value_type F2 = mask_value * (V_L_shifted * h - V_L * g);

                s0.erase(s0.begin());
                assert(s0.size() == s2.size());

                f3_loop F3_loop =
                    f3_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), s0.size());
                typename f3_loop::input_type F3_loop_input = {instance_input.alphas, s0, s2};

                typename f3_loop::result_type F3_loop_result =
                    generate_assignments(F3_loop, assignment, F3_loop_input, row);

                typename BlueprintFieldType::value_type F3 = var_value(assignment, F3_loop_result.output);
                row += F3_loop.rows_amount;

                mul_input = {F3_loop_result.output, instance_input.L0};
                mul_result = generate_assignments(mul_instance, assignment, mul_input, row);
                row += mul_instance.rows_amount;

                F3 = F3 * L0;
                assert(F3 == var_value(assignment, mul_result.output));

                assignments.clear();
                assignments.push_back(V_L);
                assignments.push_back(L0);
                assignments.push_back(F0);
                assignments.push_back(q_last);
                assignments.push_back(F1);

                std::size_t r = 0, i = 0, j = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / witness_amount;
                    j = i % witness_amount;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r + 1;

                assignments.clear();
                assignments.push_back(V_L);
                assignments.push_back(mask_value);
                assignments.push_back(h);
                assignments.push_back(V_L_shifted);
                assignments.push_back(g);
                assignments.push_back(F2);

                for (i = 0; i < assignments.size(); i++) {
                    r = i / witness_amount;
                    j = i % witness_amount;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r;

                return typename plonk_lookup_verifier<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_lookup_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType>::input_type
                    instance_input) {

                using var = typename plonk_lookup_verifier<BlueprintFieldType>::var;
                std::size_t witness_amount = component.witness_amount();

                std::vector<std::size_t> selectors;

                auto constraint = var(component.W(2), 0) - (1 - (var(component.W(1), 0) + var(component.W(0), 0)));
                selectors.push_back(bp.add_gate(constraint));

                std::vector<std::pair<std::size_t, std::size_t>> locs;

                std::size_t r = 0, j = 0;
                for (std::size_t i = 0; i < 5; i++) {
                    r = i / witness_amount;
                    j = i % witness_amount;
                    locs.push_back(std::make_pair(j, r));
                }

                auto _vl = var(component.W(locs[0].first), locs[0].second);
                auto _l0 = var(component.W(locs[1].first), locs[1].second);
                auto _f0 = var(component.W(locs[2].first), locs[2].second);
                auto _q_last = var(component.W(locs[3].first), locs[3].second);
                auto _f1 = var(component.W(locs[4].first), locs[4].second);

                auto constraint_3 = _f0 - (1 - _vl) * _l0;
                auto constraint_4 = _f1 - _q_last * (_vl * _vl - _vl);

                selectors.push_back(bp.add_gate({constraint_3, constraint_4}));

                locs.clear();
                for (std::size_t i = 0; i < 6; i++) {
                    r = i / witness_amount;
                    j = i % witness_amount;
                    locs.push_back(std::make_pair(j, r));
                }

                _vl = var(component.W(locs[0].first), locs[0].second);
                auto _m = var(component.W(locs[1].first), locs[1].second);
                auto _h = var(component.W(locs[2].first), locs[2].second);
                auto _vl2 = var(component.W(locs[3].first), locs[3].second);
                auto _g = var(component.W(locs[4].first), locs[4].second);
                auto _f2 = var(component.W(locs[5].first), locs[5].second);

                auto constraint_5 = _f2 - _m * (_vl2 * _h - _vl * _g);
                selectors.push_back(bp.add_gate({constraint_5}));

                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_lookup_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                using var = typename plonk_lookup_verifier<BlueprintFieldType>::var;
                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                    ArithmetizationType;

                using f1_loop = detail::f1_loop<ArithmetizationType>;
                using f3_loop = detail::f3_loop<ArithmetizationType>;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.q_last[0]});
                bp.add_copy_constraint({var(component.W(0), row + 1, false), instance_input.q_last[1]});
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.q_blind[0]});
                bp.add_copy_constraint({var(component.W(1), row + 1, false), instance_input.q_blind[1]});

                row += 2;

                std::size_t lu_value_size = 0;
                for (std::size_t i = 0; i < component.lookup_tables_size; i++) {
                    for (std::size_t j = 0; j < component.lookup_table_lookup_options_sizes[i]; j++) {
                        row += 2 * gate_component::get_rows_amount(witness_amount, 0,
                                                                   component.lookup_table_columns_numbers[i]);
                        row += 2 * mul::get_rows_amount(witness_amount, 0);
                        lu_value_size++;
                    }
                }

                std::size_t lu_input_size = 0;
                for (std::size_t g_id = 0; g_id < component.lookup_gates_size; g_id++) {
                    for (std::size_t c_id = 0; c_id < component.lookup_gate_constraints_sizes[g_id]; c_id++) {
                        std::size_t lookup_input_size =
                            component.lookup_gate_constraints_lookup_input_sizes[lu_input_size];
                        row += gate_component::get_rows_amount(witness_amount, 0, lookup_input_size);
                        lu_input_size++;
                    }
                }

                std::size_t m = lu_value_size + lu_input_size;
                row += f1_loop::get_rows_amount(witness_amount, 0, m);
                std::size_t h_output_col = (3 * m) % (witness_amount - 1);
                if (h_output_col == 0) {
                    h_output_col = witness_amount - 1;
                }
                std::size_t h_row_offset = 1;
                if(3*m + 1 <= witness_amount){
                    h_row_offset = 2;
                }
                var h_var = var(component.W(h_output_col), row - h_row_offset, false);
                row += f1_loop::get_rows_amount(witness_amount, 0, lu_value_size);
                row += f1_loop::get_rows_amount(witness_amount, 0, lu_input_size);
                row += mul::get_rows_amount(witness_amount, 0);
                var g_var = var(component.W(2), row - 1, false);
                row += f3_loop::get_rows_amount(witness_amount, 0, m - 1);
                row += mul::get_rows_amount(witness_amount, 0);

                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.V_L_values[0]});
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.L0});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input.q_last[0]});

                row += 4 / witness_amount + 1;
                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.V_L_values[0]});
                bp.add_copy_constraint({var(component.W(1), row, false), var(component.W(2), start_row_index, false)});
                bp.add_copy_constraint({var(component.W(2), row, false), h_var});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input.V_L_values[1]});
                bp.add_copy_constraint({var(component.W(4 % witness_amount), row + 4 / witness_amount, false), g_var});
            }

            template<typename BlueprintFieldType>
            typename plonk_lookup_verifier<BlueprintFieldType>::result_type generate_circuit(
                const plonk_lookup_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_lookup_verifier<BlueprintFieldType>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                using var = typename plonk_lookup_verifier<BlueprintFieldType>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                    ArithmetizationType;

                using f1_loop = detail::f1_loop<ArithmetizationType>;
                using f3_loop = detail::f3_loop<ArithmetizationType>;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                std::vector<std::uint32_t> witnesses;
                for (std::uint32_t i = 0; i < witness_amount; i++) {
                    witnesses.push_back(component.W(i));
                }

                var var_mask = var(component.W(2), row, false);
                var var_shifted_mask = var(component.W(2), row + 1, false);

                row += 2;

                std::vector<var> lookup_values;
                std::vector<var> shifted_lookup_values;

                std::size_t start_pos = 0, offset = 0;
                std::size_t num_tables = instance_input.lookup_table_selectors.size();
                assert(num_tables == component.lookup_tables_size);
                for (std::size_t i = 0; i < num_tables; i++) {
                    var selector = instance_input.lookup_table_selectors[i];
                    var shifted_selector = instance_input.shifted_lookup_table_selectors[i];
                    var t_id_inc = var(component.C(0), start_row_index + i, false, var::column_type::constant);

                    for (std::size_t j = 0; j < component.lookup_table_lookup_options_sizes[i]; j++) {
                        offset = component.lookup_table_columns_numbers[i];
                        std::vector<var> gate_constraints;
                        gate_constraints.push_back(t_id_inc);
                        gate_constraints.insert(gate_constraints.end(),
                                                instance_input.lookup_table_lookup_options.begin() + start_pos,
                                                instance_input.lookup_table_lookup_options.begin() + start_pos +
                                                    offset);

                        gate_component gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                                      std::array<std::uint32_t, 1>(), offset);

                        typename gate_component::input_type gate_input = {instance_input.theta, gate_constraints,
                                                                          selector};

                        typename gate_component::result_type gate_i_result =
                            generate_circuit(gate_instance, bp, assignment, gate_input, row);

                        row += gate_instance.rows_amount;

                        mul mul_instance =
                            mul(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>());

                        typename mul::input_type mul_input = {gate_i_result.output, var_mask};
                        typename mul::result_type mul_result =
                            generate_circuit(mul_instance, bp, assignment, mul_input, row);
                        row += mul_instance.rows_amount;
                        lookup_values.push_back(mul_result.output);

                        gate_constraints.clear();
                        gate_constraints.push_back(t_id_inc);
                        gate_constraints.insert(gate_constraints.end(),
                                                instance_input.shifted_lookup_table_lookup_options.begin() + start_pos,
                                                instance_input.shifted_lookup_table_lookup_options.begin() + start_pos +
                                                    offset);

                        // gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                        //                                std::array<std::uint32_t, 1>(), offset);
                        gate_input = {instance_input.theta, gate_constraints, shifted_selector};
                        gate_i_result = generate_circuit(gate_instance, bp, assignment, gate_input, row);
                        row += gate_instance.rows_amount;

                        mul_input = {gate_i_result.output, var_shifted_mask};
                        mul_result = generate_circuit(mul_instance, bp, assignment, mul_input, row);
                        row += mul_instance.rows_amount;
                        shifted_lookup_values.push_back(mul_result.output);

                        start_pos += offset;
                    }
                }
                assert(lookup_values.size() == shifted_lookup_values.size());

                std::vector<var> lookup_input;
                std::size_t start = 0, lookup_input_size = 0, ctr = 0;
                std::size_t num_gates = instance_input.lookup_gate_selectors.size();
                assert(num_gates == component.lookup_gates_size);
                for (std::size_t g_id = 0; g_id < num_gates; g_id++) {

                    var selector = instance_input.lookup_gate_selectors[g_id];
                    for (std::size_t c_id = 0; c_id < component.lookup_gate_constraints_sizes[g_id]; c_id++) {

                        lookup_input_size = component.lookup_gate_constraints_lookup_input_sizes[ctr];
                        std::vector<var> gate_constraints;
                        gate_constraints.push_back(instance_input.lookup_gate_constraints_table_ids[ctr++]);
                        gate_constraints.insert(gate_constraints.begin() + 1,
                                                instance_input.lookup_gate_constraints_lookup_inputs.begin() + start,
                                                instance_input.lookup_gate_constraints_lookup_inputs.begin() + start +
                                                    lookup_input_size);

                        gate_component gate_instance =
                            gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_input_size);
                        typename gate_component::input_type gate_input = {instance_input.theta, gate_constraints,
                                                                          selector};

                        typename gate_component::result_type gate_i_result =
                            generate_circuit(gate_instance, bp, assignment, gate_input, row);

                        lookup_input.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;
                        start += lookup_input_size;
                    }
                }

                std::vector<var> s0, s1, s2;
                std::size_t k = (instance_input.sorted.size() + 1) / 3;
                for (std::size_t i = 0; i < k; i++) {
                    s0.push_back(instance_input.sorted[i]);
                    s1.push_back(instance_input.sorted[k + i]);
                    if (i >= 1) {
                        s2.push_back(instance_input.sorted[2 * k + i - 1]);
                    }
                }

                assert(s0.size() == s1.size());

                f1_loop h_loop =
                    f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), s0.size());
                typename f1_loop::input_type h_loop_input = {instance_input.beta, instance_input.gamma, s0, s1};

                // h_loop_result
                generate_circuit(h_loop, bp, assignment, h_loop_input, row);

                row += h_loop.rows_amount;

                f1_loop g_loop_1 = f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_input.size());

                typename f1_loop::input_type g_loop_input = {instance_input.beta, instance_input.gamma, lookup_input,
                                                             lookup_input};

                typename f1_loop::result_type g_loop_result =
                    generate_circuit(g_loop_1, bp, assignment, g_loop_input, row);

                row += g_loop_1.rows_amount;

                f1_loop g_loop_2 = f1_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           lookup_values.size());

                typename f1_loop::input_type g_loop_input_2 = {instance_input.beta, instance_input.gamma, lookup_values,
                                                               shifted_lookup_values};

                typename f1_loop::result_type g_loop_result_2 =
                    generate_circuit(g_loop_2, bp, assignment, g_loop_input_2, row);

                row += g_loop_2.rows_amount;

                mul mul_instance = mul(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>());
                typename mul::input_type mul_input = {g_loop_result.output, g_loop_result_2.output};
                typename mul::result_type mul_result = generate_circuit(mul_instance, bp, assignment, mul_input, row);
                row += mul_instance.rows_amount;

                s0.erase(s0.begin());
                assert(s0.size() == s2.size());

                f3_loop F3_loop =
                    f3_loop(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(), s0.size());
                typename f3_loop::input_type F3_loop_input = {instance_input.alphas, s0, s2};

                typename f3_loop::result_type F3_loop_result =
                    generate_circuit(F3_loop, bp, assignment, F3_loop_input, row);

                row += F3_loop.rows_amount;

                mul_input = {F3_loop_result.output, instance_input.L0};
                mul_result = generate_circuit(mul_instance, bp, assignment, mul_input, row);
                row += mul_instance.rows_amount;

                std::vector<std::size_t> selectors = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selectors[0], start_row_index);
                assignment.enable_selector(selectors[0], start_row_index + 1);
                assignment.enable_selector(selectors[1], row);

                row += 4 / witness_amount + 1;
                assignment.enable_selector(selectors[2], row);

                row += 5 / witness_amount;

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_lookup_verifier<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LOOKUP_ARGUMENT_VERIFIER_HPP
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
// @file Declaration of interfaces for auxiliary components for the GATE_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/gate_component.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
            class basic_constraints_verifier;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 1> {

                constexpr static const std::uint32_t ConstantsAmount = 1;

                constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                        const std::vector<std::size_t> &gate_sizes) {

                    std::size_t r = 0;

                    for (std::size_t i = 0; i < gate_sizes.size(); i++) {
                        if (gate_sizes[i] == 1) {
                            r += mul::get_rows_amount(witness_amount, 0);
                        } else {
                            r += gate_component::get_rows_amount(witness_amount, 0, gate_sizes[i] - 1);
                        }
                    }

                    if (gate_sizes.size() > 1) {
                        std::size_t total_deg = std::accumulate(gate_sizes.begin(), gate_sizes.end() - 1, 0);
                        r += gate_component::get_rows_amount(witness_amount, 0, total_deg);
                    }

                    return r;
                }


            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, ConstantsAmount, 1>;
                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::vector<std::size_t> &gate_sizes) {
                    return rows_amount_internal(witness_amount, gate_sizes);
                }

                const std::vector<std::size_t> gate_sizes;
                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), gate_sizes);
                constexpr static const std::size_t gates_amount = 0;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 0;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::vector<std::size_t> &gate_sizes) {

                    std::vector<std::size_t>::iterator min_degree =
                        std::min_element(gate_sizes.begin(), gate_sizes.end());
                    std::vector<std::size_t>::iterator max_degree =
                        std::max_element(gate_sizes.begin(), gate_sizes.end());

                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    if (*min_degree == 1 && *max_degree > *min_degree) {
                        manifest = manifest.merge_with(mul::get_gate_manifest(witness_amount, lookup_column_amount))
                                       .merge_with(gate_component::get_gate_manifest(
                                           witness_amount, lookup_column_amount, *max_degree - 1));

                    } else if (*min_degree == 1 && *min_degree == *max_degree) {
                        manifest = manifest.merge_with(mul::get_gate_manifest(witness_amount, lookup_column_amount));

                    } else {
                        manifest = manifest.merge_with(
                            gate_component::get_gate_manifest(witness_amount, lookup_column_amount, *min_degree - 1));
                    }

                    if (gate_sizes.size() > 1 && *max_degree == 1) {
                        std::size_t total_deg = std::accumulate(gate_sizes.begin(), gate_sizes.end() - 1, 0);
                        manifest = manifest.merge_with(
                            gate_component::get_gate_manifest(witness_amount, lookup_column_amount, total_deg));
                    }

                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(3, 15)), false)
                            .merge_with(gate_component::get_manifest());
                    return manifest;
                }

                struct input_type {
                    var theta;
                    std::vector<var> constraints;
                    std::vector<var> selectors;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> vars;
                        vars.push_back(theta);
                        vars.insert(vars.end(), constraints.begin(), constraints.end());
                        vars.insert(vars.end(), selectors.begin(), selectors.end());
                        return vars;
                    }
                };

                struct result_type {
                    var output;

                    result_type(const basic_constraints_verifier &component, std::uint32_t start_row_index) {
                        if (component.gate_sizes.size() == 1 && component.gate_sizes[0] == 1) {
                            output = var(component.W(2), start_row_index + component.rows_amount - 1, false);
                        } else {
                            output = var(component.W(component.witness_amount() - 1),
                                         start_row_index + component.rows_amount - 1, false);
                        }
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                basic_constraints_verifier(ContainerType witness, std::vector<std::size_t> &gate_sizes_) :
                    component_type(witness, {}, {}, get_manifest()), gate_sizes(gate_sizes_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                basic_constraints_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                           PublicInputContainerType public_input,
                                           std::vector<std::size_t> &gate_sizes_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    gate_sizes(gate_sizes_) {};

                basic_constraints_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::vector<std::size_t> &gate_sizes_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    gate_sizes(gate_sizes_) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_basic_constraints_verifier = basic_constraints_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                // std::vector<std::size_t>::iterator max_size =
                    // std::max_element(component.gate_sizes.begin(), component.gate_sizes.end());
                // if (*max_size > 1) {
                    assignment.constant(component.C(0), start_row_index) = BlueprintFieldType::value_type::zero();
                    assignment.constant(component.C(0), start_row_index + 1) = BlueprintFieldType::value_type::one();
                // }else{
                    // assignment.constant(component.C(0), start_row_index + 1) = BlueprintFieldType::value_type::one();
                // }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType,
                                                                    ArithmetizationParams>::input_type instance_input,
                    const std::size_t start_row_index) {

                std::size_t n_sl = component.gate_sizes.size();
                std::size_t witness_amount = component.witness_amount();
                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                std::size_t row = start_row_index;
                std::vector<var> G;
                std::vector<std::uint32_t> witnesses;
                for (std::uint32_t i = 0; i < witness_amount; i++) {
                    witnesses.push_back(component.W(i));
                }
                std::size_t start = 0;
                for (std::size_t i = 0; i < n_sl; i++) {

                    std::size_t c_size = component.gate_sizes[i];
                    if (c_size == 1) {
                        mul mul_instance =
                            mul(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>());

                        typename mul::input_type mul_input = {instance_input.constraints[start], instance_input.selectors[i]};
                        typename mul::result_type mul_result =
                            generate_assignments(mul_instance, assignment, mul_input, row);
                        G.push_back(mul_result.output);
                        row += mul_instance.rows_amount;
                    } else {
                        gate_component gate_instance = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                                      std::array<std::uint32_t, 1>(), c_size - 1);

                        std::vector<var> constraints;
                        constraints.insert(constraints.begin(), instance_input.constraints.begin() + start,
                                           instance_input.constraints.begin() + start + component.gate_sizes[i]);
                        typename gate_component::input_type gate_input = {instance_input.theta, constraints,
                                                                          instance_input.selectors[i]};

                        typename gate_component::result_type gate_i_result =
                            generate_assignments(gate_instance, assignment, gate_input, row);

                        G.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;
                    }
                    start += component.gate_sizes[i];
                }

                if (n_sl > 1) {
                    std::size_t total_deg =
                        std::accumulate(component.gate_sizes.begin(), component.gate_sizes.end() - 1, 0);

                    gate_component final_gate = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                               std::array<std::uint32_t, 1>(), total_deg);

                    std::vector<var> constraints;
                    std::size_t j = 0, sum = 0;
                    for (std::size_t i = 0; i <= total_deg; i++) {
                        if (i == sum) {
                            constraints.push_back(G[j]);
                            sum += component.gate_sizes[j];
                            j++;
                        } else {
                            constraints.push_back(
                                var(component.C(0), start_row_index, false, var::column_type::constant));
                        }
                    }
                    var q = var(component.C(0), start_row_index + 1, false, var::column_type::constant);

                    typename gate_component::input_type gate_input = {instance_input.theta, constraints, q};

                    typename gate_component::result_type gate_i_result =
                        generate_assignments(final_gate, assignment, gate_input, row);

                    row += final_gate.rows_amount;
                }

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input) {

                return {};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::size_t start_row_index) {
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_basic_constraints_verifier<BlueprintFieldType,
                                                                    ArithmetizationParams>::input_type instance_input,
                    const std::size_t start_row_index) {

                using var = typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::var;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;
                using gate_component = detail::gate_component<ArithmetizationType>;
                using mul = multiplication<ArithmetizationType, BlueprintFieldType,
                                           basic_non_native_policy<BlueprintFieldType>>;

                std::size_t row = start_row_index;
                std::size_t n_sl = component.gate_sizes.size();
                std::size_t witness_amount = component.witness_amount();

                std::vector<std::uint32_t> witnesses;
                for (std::uint32_t i = 0; i < witness_amount; i++) {
                    witnesses.push_back(component.W(i));
                }

                std::size_t start = 0;
                std::vector<var> G;
                for (std::size_t i = 0; i < n_sl; i++) {
                    if (component.gate_sizes[i] == 1) {
                        mul mul_instance =
                            mul(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>());
                        typename mul::input_type mul_input = {instance_input.constraints[start], instance_input.selectors[i]};
                        typename mul::result_type mul_result =
                            generate_circuit(mul_instance, bp, assignment, mul_input, row);

                        G.push_back(mul_result.output);
                        row += mul_instance.rows_amount;
                    } else {
                        gate_component gate_instance =
                            gate_component(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 1>(),
                                           component.gate_sizes[i] - 1);
                        std::vector<var> constraints;
                        constraints.insert(constraints.begin(), instance_input.constraints.begin() + start,
                                           instance_input.constraints.begin() + start + component.gate_sizes[i]);
                        typename gate_component::input_type gate_input = {instance_input.theta, constraints,
                                                                          instance_input.selectors[i]};

                        typename gate_component::result_type gate_i_result =
                            generate_circuit(gate_instance, bp, assignment, gate_input, row);
                        G.push_back(gate_i_result.output);
                        row += gate_instance.rows_amount;
                    }
                    start += component.gate_sizes[i];
                }

                if (n_sl > 1) {

                    generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                    std::size_t total_deg =
                        std::accumulate(component.gate_sizes.begin(), component.gate_sizes.end() - 1, 0);

                    gate_component final_gate = gate_component(witnesses, std::array<std::uint32_t, 0>(),
                                                               std::array<std::uint32_t, 1>(), total_deg);

                    std::vector<var> constraints;
                    std::size_t j = 0, sum = 0;
                    for (std::size_t i = 0; i <= total_deg; i++) {
                        if (i == sum) {
                            constraints.push_back(G[j]);
                            sum += component.gate_sizes[j];
                            j++;
                        } else {
                            constraints.push_back(
                                var(component.C(0), start_row_index, false, var::column_type::constant));
                        }
                    }
                    var q = var(component.C(0), start_row_index + 1, false, var::column_type::constant);

                    typename gate_component::input_type gate_input = {instance_input.theta, constraints, q};

                    typename gate_component::result_type gate_i_result =
                        generate_circuit(final_gate, bp, assignment, gate_input, row);

                    row += final_gate.rows_amount;
                }

                std::vector<std::size_t> selectors = generate_gates(component, bp, assignment, instance_input);

                assert(selectors.empty());

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return
                    typename plonk_basic_constraints_verifier<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_ARGUMENT_VERIFIER_HPP
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

#include "nil/blueprint/components/algebra/fields/plonk/addition.hpp"
#include "nil/blueprint/components/algebra/fields/plonk/multiplication.hpp"
#include "nil/blueprint/components/systems/snark/plonk/placeholder/detail/expression_evaluation_component.hpp"
#include <unordered_map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/expression_evaluation_component.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            using detail::expression_evaluation_component;

            template<typename ArithmetizationType>
            class final_polynomial_check;

            // checks that the polynomial defined by power + 1 coefficients has values equal to 2*lambda passed values
            // at 2*lambda points of the form (s, -s)
            // (where one of the points is passed, and the other one is inferred)
            // coefficients passed highest to lowest power
            template<typename BlueprintFieldType>
            class final_polynomial_check<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {
            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using manifest_type = nil::blueprint::plonk_component_manifest;
                using expression_evaluator_type = plonk_expression_evaluation_component<BlueprintFieldType>;

                std::size_t power;
                std::size_t lambda;

                static const std::size_t rows_amount = 0;
                static const std::size_t gates_amount = 0;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    gate_manifest_type() {}

                    std::uint32_t gates_amount() const override {
                        return final_polynomial_check::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                        std::size_t witness_amount,
                        std::size_t power,
                        std::size_t labmda) {
                    static gate_manifest manifest = gate_manifest_type();
                    return manifest;
                }

                static manifest_type get_manifest(std::size_t power, std::size_t labmda) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(3)), true);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t power,
                                                             std::size_t labmda) {
                    return final_polynomial_check::rows_amount;
                }

                struct input_type {
                    std::vector<var> coefficients;
                    std::vector<var> points;
                    std::vector<var> values;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        for (auto &coefficient : coefficients) {
                            result.push_back(coefficient);
                        }
                        for (auto &point : points) {
                            result.push_back(point);
                        }
                        for (auto &value : values) {
                            result.push_back(value);
                        }
                        return result;
                    }
                };

                struct result_type {
                    // fail if the check is not satisfied
                    result_type(const final_polynomial_check &component, std::uint32_t start_row_index) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                final_polynomial_check(ContainerType witness, std::size_t power_, std::size_t lambda_) :
                    component_type(witness, {}, {}, get_manifest(power_, lambda_)),
                    power(power_), lambda(lambda_)
                {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                            typename PublicInputContainerType>
                final_polynomial_check(WitnessContainerType witness, ConstantContainerType constant,
                                       PublicInputContainerType public_input,
                                       std::size_t power_, std::size_t lambda_) :
                    component_type(witness, constant, public_input, get_manifest(power_, lambda_)),
                    power(power_), lambda(lambda_)
                {};

                final_polynomial_check(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t power_, std::size_t lambda_) :
                    component_type(witnesses, constants, public_inputs, get_manifest(power_, lambda_)),
                    power(power_), lambda(lambda_)
                {};

                inline std::tuple<constraint_type, constraint_type,
                                    std::unordered_map<var, var>> build_mapping_and_constraints(
                        const input_type &instance_input) const {

                    std::unordered_map<var, var> coefficient_mapping;
                    // map coefficients to themselves; we can directly put them into an expression
                    for (auto coefficient : instance_input.coefficients) {
                        coefficient_mapping[coefficient] = coefficient;
                    }
                    // the only relative vars present, thus cannot possibly conflict with the mapping
                    var s_var = var(0, 0, true, var::column_type::witness),
                        y_var = var(0, 1, true, var::column_type::witness);
                    constraint_type constraint_s = instance_input.coefficients[0];
                    for (std::size_t i = 1; i < instance_input.coefficients.size(); i++) {
                        constraint_s = instance_input.coefficients[i] + s_var * constraint_s;
                    }
                    constraint_s = constraint_s - y_var;
                    constraint_type constraint_m_s = instance_input.coefficients[0];
                    for (std::size_t i = 1; i < instance_input.coefficients.size(); i++) {
                        constraint_m_s = instance_input.coefficients[i] - s_var * constraint_m_s;
                    }
                    constraint_m_s = constraint_m_s - y_var;
                    return std::make_tuple(constraint_s, constraint_m_s, coefficient_mapping);
                }
            };

            template<typename BlueprintFieldType>
            using plonk_final_polynomial_check = final_polynomial_check<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_final_polynomial_check<BlueprintFieldType>::result_type generate_assignments(
                const plonk_final_polynomial_check<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_final_polynomial_check<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_final_polynomial_check<BlueprintFieldType>;
                using expression_evaluator_type = typename component_type::expression_evaluator_type;
                using expression_evaluator_input_type = typename expression_evaluator_type::input_type;
                using var = typename component_type::var;

                BOOST_ASSERT(instance_input.coefficients.size() == component.power + 1);
                BOOST_ASSERT(instance_input.points.size() == component.lambda);
                BOOST_ASSERT(instance_input.values.size() == 2 * component.lambda);

                auto mapping_and_constraints = component.build_mapping_and_constraints(instance_input);
                for (std::size_t i = 0; i < instance_input.points.size(); i++) {
                    var point = instance_input.points[i];
                    var value = instance_input.values[2 * i],
                        value_m = instance_input.values[2 * i + 1];
                    std::unordered_map<var, var> mapping = std::get<2>(mapping_and_constraints);
                    mapping.insert({var(0, 0, true, var::column_type::witness), point});
                    mapping.insert({var(0, 1, true, var::column_type::witness), value});
                    expression_evaluator_type evaluator(
                        component._W, component._C, component._PI, std::get<0>(mapping_and_constraints));
                    expression_evaluator_input_type input = {mapping};
                    generate_assignments(evaluator, assignment, input, start_row_index);
                    expression_evaluator_type evaluator_m(
                        component._W, component._C, component._PI, std::get<1>(mapping_and_constraints));
                    mapping.erase(var(0, 1, true, var::column_type::witness));
                    mapping.insert({var(0, 1, true, var::column_type::witness), value_m});
                    input = {mapping};
                    generate_assignments(evaluator_m, assignment, input, start_row_index);
                }

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_final_polynomial_check<BlueprintFieldType>::result_type generate_circuit(
                const plonk_final_polynomial_check<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_final_polynomial_check<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_final_polynomial_check<BlueprintFieldType>;
                using expression_evaluator_type = typename component_type::expression_evaluator_type;
                using expression_evaluator_input_type = typename expression_evaluator_type::input_type;
                using var = typename component_type::var;

                BOOST_ASSERT(instance_input.coefficients.size() == component.power + 1);
                BOOST_ASSERT(instance_input.points.size() == component.lambda);
                BOOST_ASSERT(instance_input.values.size() == 2 * component.lambda);

                var zero = assignment.add_batch_constant_variable(0);

                auto mapping_and_constraints = component.build_mapping_and_constraints(instance_input);
                for (std::size_t i = 0; i < instance_input.points.size(); i++) {
                    var point = instance_input.points[i];
                    var value = instance_input.values[2 * i],
                        value_m = instance_input.values[2 * i + 1];
                    std::unordered_map<var, var> mapping = std::get<2>(mapping_and_constraints);
                    mapping.insert({var(0, 0, true, var::column_type::witness), point});
                    mapping.insert({var(0, 1, true, var::column_type::witness), value});
                    expression_evaluator_type evaluator(
                        component._W, component._C, component._PI, std::get<0>(mapping_and_constraints));
                    expression_evaluator_input_type input = {mapping};
                    auto result = generate_circuit(evaluator, bp, assignment, input, start_row_index);
                    bp.add_copy_constraint({result.output, zero});
                    expression_evaluator_type evaluator_m(
                        component._W, component._C, component._PI, std::get<1>(mapping_and_constraints));
                    mapping.erase(var(0, 1, true, var::column_type::witness));
                    mapping.insert({var(0, 1, true, var::column_type::witness), value_m});
                    input = {mapping};
                    auto result_m = generate_circuit(evaluator_m, bp, assignment, input, start_row_index);
                    bp.add_copy_constraint({result_m.output, zero});
                }

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

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

#include "nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp"
#include "nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp"
#include "nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp"
#include "nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp"
#include <unordered_map>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename BlueprintFieldType, typename ArithmetizationType>
                class expression_to_execution_simple :
                    public boost::static_visitor<nil::crypto3::zk::snark::plonk_variable<
                        typename BlueprintFieldType::value_type>> {
                public:
                    using value_type = typename BlueprintFieldType::value_type;
                    using var = nil::crypto3::zk::snark::plonk_variable<value_type>;
                    using assignment_type = assignment<ArithmetizationType>;
                    using multiplication_component_type = nil::blueprint::components::multiplication<
                            ArithmetizationType, BlueprintFieldType,
                            nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;
                    using addition_component_type = nil::blueprint::components::addition<
                            ArithmetizationType, BlueprintFieldType,
                            nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;
                    using subtraction_component_type = nil::blueprint::components::subtraction<
                            ArithmetizationType, BlueprintFieldType,
                            nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

                    expression_to_execution_simple(assignment_type &_assignment,
                                                   const std::unordered_map<var, var> &_variable_map,
                                                   bool _generate_assignment_call)
                        : assignment(_assignment), variable_map(_variable_map),
                          generate_assignment_call(_generate_assignment_call)
                    {}

                    var visit(const nil::crypto3::math::expression<var> &expr) {
                        return boost::apply_visitor(*this, expr.get_expr());
                    }

                    var operator()(const nil::crypto3::math::term<var>& term) {
                        var result;
                        const std::size_t term_size = term.get_vars().size();
                        if (term_size == 0) {
                            return assignment.add_batch_constant_variable(term.get_coeff());
                        }
                        std::size_t curr_term = 0;
                        if (term.get_coeff() != value_type::one()) {
                            auto coeff_var = assignment.add_batch_constant_variable(term.get_coeff());
                            result = assignment.template add_input_to_batch<multiplication_component_type>(
                                {coeff_var, variable_map.at(term.get_vars()[curr_term])},
                                generate_assignment_call).output;
                        } else {
                            result = variable_map.at(term.get_vars()[curr_term]);
                        }
                        curr_term++;
                        for (; curr_term < term_size; curr_term++) {
                            result = assignment.template add_input_to_batch<multiplication_component_type>(
                                {result, variable_map.at(term.get_vars()[curr_term])},
                                generate_assignment_call).output;
                        }
                        return result;
                    }

                    var operator()(const nil::crypto3::math::pow_operation<var>& pow) {
                        int power = pow.get_power();
                        BOOST_ASSERT(power > 0);
                        var expr_res = boost::apply_visitor(*this, pow.get_expr().get_expr());
                        if (power == 1) {
                            return expr_res;
                        }
                        var result = assignment.add_batch_constant_variable(value_type::one());
                        while (power > 1) {
                            if (power % 2 == 0) {
                                expr_res = assignment.template add_input_to_batch<multiplication_component_type>(
                                    {expr_res, expr_res},
                                    generate_assignment_call).output;
                                power /= 2;
                            } else {
                                result = assignment.template add_input_to_batch<multiplication_component_type>(
                                    {result, expr_res},
                                    generate_assignment_call).output;
                                power -= 1;
                            }
                        }
                        return assignment.template add_input_to_batch<multiplication_component_type>(
                                {result, expr_res},
                                generate_assignment_call).output;
                    }

                    var operator()(const nil::crypto3::math::binary_arithmetic_operation<var>& op) {
                        auto res1 = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                        auto res2 = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                        switch (op.get_op()) {
                            case crypto3::math::ArithmeticOperator::ADD:
                                return assignment.template add_input_to_batch<addition_component_type>(
                                            {res1, res2},
                                            generate_assignment_call).output;
                            case crypto3::math::ArithmeticOperator::SUB:
                                return assignment.template add_input_to_batch<subtraction_component_type>(
                                            {res1, res2},
                                            generate_assignment_call).output;
                            case crypto3::math::ArithmeticOperator::MULT:
                                return assignment.template add_input_to_batch<multiplication_component_type>(
                                            {res1, res2},
                                            generate_assignment_call).output;
                            default:
                                throw std::runtime_error("Unsupported operation");
                        }
                    }
                private:
                    assignment_type &assignment;
                    const std::unordered_map<var, var> &variable_map;
                    bool generate_assignment_call;
                };

                template<typename ArithmetizationType>
                class expression_evaluation_component;

                // Brute-force expression evaluation
                // Should be relatively easy to repurpose for more opitmised versions
                template<typename BlueprintFieldType>
                class expression_evaluation_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    : public plonk_component<BlueprintFieldType> {
                public:
                    using component_type = plonk_component<BlueprintFieldType>;

                    using var = typename component_type::var;
                    using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                    using manifest_type = nil::blueprint::plonk_component_manifest;
                    using expression_evaluator_type = expression_to_execution_simple<
                        BlueprintFieldType, crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

                    constraint_type constraint;

                    // What do we even do with this if we are batching?
                    static const std::size_t rows_amount = 0;
                    static const std::size_t gates_amount = 0;

                    class gate_manifest_type : public component_gate_manifest {
                    public:
                        gate_manifest_type() {}

                        std::uint32_t gates_amount() const override {
                            return expression_evaluation_component::gates_amount;
                        }
                    };

                    static gate_manifest get_gate_manifest(
                            std::size_t witness_amount,
                            constraint_type &constraint) {
                        static gate_manifest manifest = gate_manifest_type();
                        // TODO: should we intersect with batched gates?
                        return manifest;
                    }

                    static manifest_type get_manifest(constraint_type &constraint) {
                        static manifest_type manifest =
                            manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(3)), true);
                        return manifest;
                    }

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                 constraint_type &constraint) {
                        return expression_evaluation_component::rows_amount;
                    }

                    struct input_type {
                        std::unordered_map<var, var> variable_mapping;

                        std::vector<std::reference_wrapper<var>> all_vars() {
                            std::vector<std::reference_wrapper<var>> result;
                            for (auto &pair : variable_mapping) {
                                result.push_back(pair.second);
                            }
                            return result;
                        }
                    };

                    struct result_type {
                        var output;

                        result_type(var output_, std::size_t start_row_index) : output(output_) {}
                        result_type(var output_) : output(output_) {}

                        std::vector<std::reference_wrapper<var>> all_vars() {
                            return {output};
                        }
                    };

                    template<typename ContainerType>
                    expression_evaluation_component(ContainerType witness, constraint_type constraint_) :
                        component_type(witness, {}, {}, get_manifest(constraint_)), constraint(constraint_)
                    {};

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    expression_evaluation_component(WitnessContainerType witness, ConstantContainerType constant,
                                            PublicInputContainerType public_input, constraint_type constraint_) :
                        component_type(witness, constant, public_input, get_manifest(constraint_)), constraint(constraint_)
                    {};

                    expression_evaluation_component(
                        std::initializer_list<typename component_type::witness_container_type::value_type>
                            witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        constraint_type constraint_) :
                        component_type(witnesses, constants, public_inputs, get_manifest(constraint_)), constraint(constraint_)
                    {};
                };
            }    // namespace detail

            template<typename BlueprintFieldType>
            using plonk_expression_evaluation_component = detail::expression_evaluation_component<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_expression_evaluation_component<BlueprintFieldType>::result_type generate_assignments(
                const plonk_expression_evaluation_component<BlueprintFieldType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_expression_evaluation_component<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_expression_evaluation_component<BlueprintFieldType>;
                using expression_evaluator_type = typename component_type::expression_evaluator_type;

                expression_evaluator_type evaluator(assignment, instance_input.variable_mapping, true);
                return typename component_type::result_type(evaluator.visit(component.constraint), start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_expression_evaluation_component<BlueprintFieldType>::result_type generate_circuit(
                const plonk_expression_evaluation_component<BlueprintFieldType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_expression_evaluation_component<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_expression_evaluation_component<BlueprintFieldType>;
                using expression_evaluator_type = typename component_type::expression_evaluator_type;

                expression_evaluator_type evaluator(assignment, instance_input.variable_mapping, false);
                return typename component_type::result_type(evaluator.visit(component.constraint), start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

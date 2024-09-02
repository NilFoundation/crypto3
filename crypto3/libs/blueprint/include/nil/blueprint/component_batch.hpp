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

#include <functional>
#include <string>
#include <vector>
#include <numeric>
#include <utility>
#include <unordered_map>
#include <map>

#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/utils/gate_mover.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename BlueprintFieldType, typename InputType>
            struct comparison_for_inputs_results {
                bool operator()(const InputType &lhs, const InputType &rhs) const {
                    // all_vars is not const, so we const_cast here
                    // we do not modify anything I swear
                    // copying into non-const is inefficient, and this would get called a ton for large batch sizes
                    InputType &lhs_input = const_cast<InputType&>(lhs);
                    InputType &rhs_input = const_cast<InputType&>(rhs);
                    auto lhs_vars = lhs_input.all_vars();
                    auto rhs_vars = rhs_input.all_vars();
                    auto result = std::lexicographical_compare(
                        lhs_vars.begin(), lhs_vars.end(),
                        rhs_vars.begin(), rhs_vars.end(),
                        [](const auto &lhs, const auto &rhs) {
                            return lhs.get() < rhs.get();
                        }
                    );
                    return result;
                }
            };

            template<typename ComponentType, typename WitnessContainerType, typename ConstantContainerType,
                     typename PublicInputContainerType, typename... ComponentParams>
            ComponentType component_builder(
                WitnessContainerType witnesses,
                ConstantContainerType constants,
                PublicInputContainerType public_inputs,
                const std::tuple<ComponentParams...> &params) {

                auto construct = [&witnesses, &constants, &public_inputs](auto... args) {
                    return ComponentType(
                        std::forward<WitnessContainerType>(witnesses), std::forward<ConstantContainerType>(constants),
                        std::forward<PublicInputContainerType>(public_inputs),
                        std::forward<decltype(args)>(args)...);
                };

                return std::apply(construct, params);
            }
        }   // namespace detail

        using detail::comparison_for_inputs_results;

        struct _batch;

        template<typename ArithmetizationType>
        class assignment;

        template<typename ArithmetizationType>
        class circuit;

        template<typename ComponentType>
        struct input_type_v {
            typedef typename ComponentType::input_type type;
        };

        template<>
        struct input_type_v<_batch> {
            typedef typename boost::mpl::identity<void> type;
        };

        template<typename ComponentType>
        struct result_type_v {
            typedef typename ComponentType::result_type type;
        };

        template<>
        struct result_type_v<_batch> {
            typedef typename boost::mpl::identity<void> type;
        };

        template<typename ComponentType>
        struct component_params_type_v {
            typedef typename ComponentType::component_params_type type;
        };

        template<>
        struct component_params_type_v<_batch> {
            typedef typename boost::mpl::identity<void> type;
        };

        template<typename BatchType, typename InputType, typename ResultType>
        struct has_add_input {
            static ResultType apply(BatchType& batch, const InputType& input) {
                return batch.add_input(input);
            }
        };

        template<typename BatchType, typename ArithmetizationType, typename VariableType>
        struct has_finalize_batch {
            static std::size_t apply(BatchType& batch, nil::blueprint::circuit<ArithmetizationType> &bp,
                                     std::unordered_map<VariableType, VariableType> &variable_map,
                                     const std::uint32_t start_row_index) {
                return batch.finalize_batch(bp, variable_map, start_row_index);
            }
        };

        template<typename BatchType>
        struct has_name {
            static std::string apply(const BatchType& batch) {
                return batch.name();
            }
        };

        // Generic-ish enough batching solution for single-line components
        // Lookups currently unsupported
        // Partially supports component prarameterization -- only if passed through template parameters
        template<typename ArithmetizationType, typename BlueprintFieldType, typename ComponentType,
                 typename... ComponentParams>
        class component_batch {
        public:
            using input_type = typename ComponentType::input_type;
            using result_type = typename ComponentType::result_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = crypto3::zk::snark::plonk_variable<value_type>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using gate_type = crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
            using component_params_type = typename std::tuple<ComponentParams...>;
            // input-output pairs for batched components
            // the second bool determines whether the result has been actually filled; is left unfilled if called
            // from generate_circuit
            std::map<input_type, std::pair<result_type, bool>, comparison_for_inputs_results<BlueprintFieldType, input_type>>
                inputs_results;
            // pointer to the assignment we are going to use in the end
            assignment<ArithmetizationType> &parent_assignment;
            // we cache this; use this to store intermediate results
            assignment<ArithmetizationType> internal_assignment;
            // stroing the component parameters
            std::tuple<ComponentParams...> params_tuple;

            std::function<ComponentType(
                    std::vector<std::size_t>, std::vector<std::size_t>, std::vector<std::size_t>,
                    const std::tuple<ComponentParams...>&)>
                component_builder = detail::component_builder<
                    ComponentType,
                    std::vector<std::size_t>, std::vector<std::size_t>, std::vector<std::size_t>,
                    ComponentParams...>;

            component_batch(assignment<ArithmetizationType> &_assignment,
                            component_params_type params)
                : parent_assignment(_assignment),
                  internal_assignment(_assignment.witnesses_amount(), 1, 0, 0),
                  params_tuple(params)
            {}

            ~component_batch() = default;

            std::string name() const {
                std::string result = typeid(ComponentType).name();
                std::apply([&result](auto... args) {
                    ((result += "__" + std::to_string(args)), ...);
                }, params_tuple);
                return result;
            }

            void variable_transform(std::reference_wrapper<var> variable) {
                variable.get() = parent_assignment.add_batch_variable(
                    var_value(internal_assignment, variable.get()));
            }

            ComponentType build_component_instance(const std::size_t component_witness_amount,
                                                   const std::size_t start_value = 0) const {
                const std::vector<std::size_t> constants = {}, public_inputs = {};
                std::vector<std::size_t> witness_columns(component_witness_amount);
                std::iota(witness_columns.begin(), witness_columns.end(), start_value);
                return std::apply(component_builder, std::make_tuple(witness_columns, constants, public_inputs, params_tuple));
            }

            std::size_t get_component_witness_amount() const {
                const compiler_manifest assignment_manifest(parent_assignment.witnesses_amount(), false);
                const auto component_manifest = std::apply(ComponentType::get_manifest, params_tuple);
                const auto intersection = assignment_manifest.intersect(component_manifest);
                BOOST_ASSERT_MSG(intersection.is_satisfiable(), "Component either has a constant or does not fit");
                const std::size_t component_witness_amount = intersection.witness_amount->max_value_if_sat();
                return component_witness_amount;
            }

            // call this in both generate_assignments and generate_circuit
            result_type add_input(const input_type &input, bool called_from_generate_circuit = false) {
                // short-circuit if the input has already been through batching
                bool unassigned_result_found = false;
                if (inputs_results.find(input) != inputs_results.end()) {
                    auto result_pair = inputs_results.at(input);
                    if (result_pair.second || called_from_generate_circuit) {
                        return result_pair.first;
                    }
                    unassigned_result_found = true;
                }

                std::size_t component_witness_amount = get_component_witness_amount();
                ComponentType component_instance = build_component_instance(component_witness_amount);

                if (called_from_generate_circuit) {
                    // if we found a result we have already returned before this point
                    // generating a dummy result
                    result_type result(component_instance, 0);
                    for (auto variable : result.all_vars()) {
                        variable.get() = parent_assignment.add_batch_variable(0);
                    }
                    bool insertion_result = inputs_results.insert({input, {result, false}}).second;
                    BOOST_ASSERT(insertion_result);
                    return result;
                }

                // now we need to actually calculate the result without instantiating the component
                // luckily, we already have the mechanism for that
                input_type input_copy = input;
                std::vector<std::reference_wrapper<var>> vars = input_copy.all_vars();
                std::vector<value_type> values;
                for (const auto &var : vars) {
                    values.push_back(var_value(parent_assignment, var.get()));
                }
                // safety resize for the case where parent assignment got resized during the lifetime
                internal_assignment.resize_witnesses(component_witness_amount);
                // move the variables to internal_assignment's public_input column
                for (std::size_t i = 0 ; i < vars.size(); i++) {
                    internal_assignment.public_input(0, i) = values[i];
                    vars[i].get() = var(0, i, false, var::column_type::public_input);
                }
                auto result = generate_empty_assignments(component_instance, internal_assignment, input_copy, 0);
                // and replace the variables with placeholders, while saving their values
                if (!unassigned_result_found) {
                    for (auto variable : result.all_vars()) {
                        variable_transform(variable);
                    }
                    bool insertion_result = inputs_results.insert({input, {result, true}}).second;
                    BOOST_ASSERT(insertion_result);
                    return result;
                } else {
                    // already have some vars
                    auto unassigned_result = inputs_results.find(input)->second.first;
                    auto unsassigned_vars = unassigned_result.all_vars();
                    auto result_vars = result.all_vars();
                    BOOST_ASSERT(unsassigned_vars.size() == result_vars.size());
                    for (std::size_t i = 0; i < unsassigned_vars.size(); i++) {
                        parent_assignment.batch_private_storage(unsassigned_vars[i].get().rotation) =
                            var_value(internal_assignment, result_vars[i].get());
                    }
                    inputs_results.erase(input);
                    bool insertion_result = inputs_results.insert({input, {unassigned_result, true}}).second;
                    BOOST_ASSERT(insertion_result);
                    return unassigned_result;
                }
            }

            // call this once in the end in assignment
            // note that the copy constraint replacement is done by assignment in order to reduce the amount of
            // spinning through the constraints; we pass variable_map for this purpose
            // returns the first free row index
            std::size_t finalize_batch(
                    circuit<ArithmetizationType> &bp,
                    std::unordered_map<var, var> &variable_map,
                    const std::uint32_t start_row_index) {

                if (inputs_results.empty()) {
                    return start_row_index;
                }
                // First figure out how much we can scale the component
                const std::size_t component_witness_amount = get_component_witness_amount();
                std::size_t row = start_row_index,
                            col_offset = 0;
                const std::vector<std::size_t> constants = {}, public_inputs = {};
                std::size_t gate_id = generate_batch_gate(
                    bp, inputs_results.begin()->first, component_witness_amount);
                for (auto &input_result : inputs_results) {
                    const input_type &input = input_result.first;
                    result_type &result = input_result.second.first;
                    bool result_status = input_result.second.second;
                    BOOST_ASSERT(result_status);
                    if (col_offset == 0) {
                        parent_assignment.enable_selector(gate_id, row);
                    }
                    ComponentType component_instance = build_component_instance(component_witness_amount, col_offset);
                    auto actual_result = generate_assignments(component_instance, parent_assignment, input, row);
                    generate_copy_constraints(component_instance, bp, parent_assignment, input, row);
                    std::size_t vars_amount = result.all_vars().size();
                    for (std::size_t i = 0; i < vars_amount; i++) {
                        const var batch_var = result.all_vars()[i].get();
                        variable_map[batch_var] = actual_result.all_vars()[i].get();
                    }

                    col_offset += component_witness_amount;
                    if (col_offset + component_witness_amount - 1 >= parent_assignment.witnesses_amount()) {
                        col_offset = 0;
                        row += 1;
                    }
                }
                // we fill the unused places with copies of components for the first input to satisfy the gate
                if (col_offset != 0 &&
                    (col_offset + component_witness_amount - 1 < parent_assignment.witnesses_amount())) {

                    while (col_offset + component_witness_amount - 1 < parent_assignment.witnesses_amount()) {
                        std::vector<std::size_t> witness_columns(component_witness_amount);
                        std::iota(witness_columns.begin(), witness_columns.end(), col_offset);
                        ComponentType component_instance =
                            std::apply(component_builder, std::make_tuple(witness_columns, constants, public_inputs, params_tuple));
                        generate_assignments(component_instance, parent_assignment, inputs_results.begin()->first, row);
                        col_offset += component_witness_amount;
                    }
                    row += 1;
                }
                return row;
            }

            std::vector<constraint_type> move_constraints(
                    const std::vector<constraint_type>& constraints,
                    const std::size_t offset) {

                gate_mover<BlueprintFieldType> mover([&offset](var v) -> var {
                    return var(v.index + offset, v.rotation, v.relative, v.type);
                });
                std::vector<constraint_type> result;
                for (const auto& constraint : constraints) {
                    result.push_back(mover.visit(constraint));
                }
                return result;
            }

            std::size_t generate_batch_gate(
                    circuit<ArithmetizationType> &bp,
                    const input_type &example_input,
                    const std::size_t component_witness_amount) {

                circuit<ArithmetizationType> tmp_bp;
                ComponentType component_instance = build_component_instance(component_witness_amount);
                generate_gates(component_instance, tmp_bp, parent_assignment, example_input);
                const auto &gates = tmp_bp.gates();
                BOOST_ASSERT(gates.size() == 1);

                std::vector<constraint_type> new_gate_constraints, one_gate_constraints;
                auto curr_gate = gates[0];
                for (const auto &constraint : curr_gate.constraints) {
                    new_gate_constraints.push_back(constraint);
                    one_gate_constraints.push_back(constraint);
                }
                const std::size_t scaling_amount = parent_assignment.witnesses_amount() / component_witness_amount;
                // Technically, we could generate 'not full' gate for the last batch
                // We are unlikely to be able to use that space for anything else, so we reduce the amount of selectors
                for (std::size_t i = 1; i < scaling_amount; i++) {
                    auto moved_constraints = move_constraints(one_gate_constraints, i * component_witness_amount);
                    for (auto &constraint : moved_constraints) {
                        new_gate_constraints.push_back(constraint);
                    }
                }
                return bp.add_gate(new_gate_constraints);
            }

            template<typename OtherBatchType>
            bool operator<(const OtherBatchType &other) const {
                if (std::type_index(typeid(*this)) != std::type_index(typeid(other))) {
                    return std::type_index(typeid(*this)) < std::type_index(typeid(other));
                } else {
                    const auto &other_batch = reinterpret_cast<
                        const component_batch<ArithmetizationType, BlueprintFieldType,
                                              ComponentType, ComponentParams...>&>(other);
                    // compare params_tuple
                    return params_tuple < other_batch.params_tuple;
                }
            }
        };
    }        // namespace blueprint
}    // namespace nil

namespace boost {
    namespace type_erasure {
        template<typename BatchType, typename InputType, typename ResultType, typename Base>
        struct concept_interface<nil::blueprint::has_add_input<BatchType, InputType, ResultType>, Base, BatchType>
                : Base {

            ResultType add_input(typename as_param<Base, const InputType&>::type input,
                                 bool called_from_generate_circuit) {
                return call(nil::blueprint::has_add_input<BatchType, InputType, ResultType>(), *this, input,
                            called_from_generate_circuit);
            }
        };

        template<typename BatchType, typename ArithmetizationType, typename VariableType, typename Base>
        struct concept_interface<nil::blueprint::has_finalize_batch<BatchType, ArithmetizationType, VariableType>,
                                 Base, BatchType> : Base {
            std::size_t finalize_batch(
                    typename as_param<Base, nil::blueprint::circuit<ArithmetizationType>&>::type bp,
                    typename as_param<Base, std::unordered_map<VariableType, VariableType>&>::type variable_map,
                    typename as_param<Base, const std::uint32_t>::type start_row_index) {

                return call(nil::blueprint::has_finalize_batch<BatchType, ArithmetizationType, VariableType>(), *this,
                            bp, variable_map, start_row_index);
            }
        };

        template<typename BatchType, typename Base>
        struct concept_interface<nil::blueprint::has_name<BatchType>, Base, BatchType> : Base {
            std::string name() const {
                return call(nil::blueprint::has_name<BatchType>(), *this);
            }
        };
    }   // namespace type_erasure
}   // namespace boost

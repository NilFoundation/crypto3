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

#ifndef CRYPTO3_BLUEPRINT_UTILS_PLONK_CONNECTEDNESS_CHECK_HPP
#define CRYPTO3_BLUEPRINT_UTILS_PLONK_CONNECTEDNESS_CHECK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/math/expression.hpp>

#include <boost/pending/disjoint_sets.hpp>
#include <boost/assert.hpp>

#include <vector>
#include <set>
#include <unordered_set>
#include <array>
#include <iostream>
#include <algorithm>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename BlueprintFieldType>
            std::size_t copy_var_address(
                const std::size_t row_size,
                const std::size_t start_row_index, const std::size_t rows_amount,
                const nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &variable) {

                using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                const std::size_t ouptutless_var_amount = row_size * rows_amount;

                if (variable.type == var::column_type::public_input) {
                    // Assumes a single file public input
                    return ouptutless_var_amount + variable.rotation;
                } else if (variable.type == var::column_type::witness) {
                    return (variable.rotation - start_row_index) * row_size + variable.index;
                } else {
                    // Constant
                    return (variable.rotation - start_row_index) * row_size + row_size - 1;
                }
            };

            template<typename BlueprintFieldType>
            void export_connectedness_zones(
                boost::disjoint_sets_with_storage<> zones,
                const nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const std::vector<std::reference_wrapper<nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                    &input_variables,
                const std::size_t start_row_index, std::size_t rows_amount,
                std::ostream &os) {

                using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                const std::size_t row_size = assignment.witnesses_amount() + assignment.constants_amount();
                const std::size_t end_row = start_row_index + rows_amount;

                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> output_assignment(
                    assignment.witnesses_amount(), assignment.constants_amount(),
                    assignment.public_inputs_amount(), assignment.selectors_amount()
                );

                // We do '+1' in all the assignments to separate the unassigned cells (0 by default)
                // from the ones which actually got checked.
                for (std::size_t witness_column = 0; witness_column < row_size; witness_column++) {
                    std::size_t last_row =
                        std::min<std::size_t>(end_row, assignment.witness_column_size(witness_column));
                    for (std::size_t row = start_row_index; row < last_row; row++) {
                        output_assignment.witness(witness_column, row) =
                            zones.find_set(copy_var_address<BlueprintFieldType>(
                                row_size, start_row_index, rows_amount,
                                var(witness_column, row, false, var::column_type::witness))) + 1;
                    }
                }
                for (std::size_t constant_column = 0; constant_column < assignment.constants_amount();
                     constant_column++) {

                    std::size_t last_row =
                        std::min<std::size_t>(end_row, assignment.constant_column_size(constant_column));
                    for (std::size_t row = start_row_index; row < last_row; row++) {
                        output_assignment.constant(constant_column, row) =
                            zones.find_set(copy_var_address<BlueprintFieldType>(
                                row_size, start_row_index, rows_amount,
                                var(constant_column, row, false, var::column_type::constant))) + 1;
                    }
                }
                for (auto &variable : input_variables) {
                    const auto output_value =
                        zones.find_set(copy_var_address<BlueprintFieldType>(
                                       row_size, start_row_index, rows_amount, variable)) + 1;
                    switch (variable.type) {
                        case var::column_type::constant:
                            output_assignment.constant(variable.index, variable.rotation) = output_value;
                            break;
                        case var::column_type::public_input:
                            output_assignment.public_input(variable.index, variable.rotation) = output_value;
                            break;
                        case var::column_type::witness:
                            output_assignment.witness(variable.index, variable.rotation) = output_value;
                            break;
                        case var::column_type::selector:
                            BOOST_ASSERT_MSG(false, "Selector variables should not be input variables.");
                            break;
                    }
                }
                // Copy selectors over from assignment
                for (std::size_t selector = 0; selector < assignment.selectors_amount(); selector++) {
                    std::size_t last_row =
                        std::min<std::size_t>(end_row, assignment.selector_column_size(selector));
                    for (std::size_t row = start_row_index; row < last_row; row++) {
                        output_assignment.selector(selector, row) =
                            assignment.selector(selector, row);
                    }
                }
                output_assignment.export_table(os);
            }

            template<typename BlueprintFieldType>
            void mark_set(
                const nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                boost::disjoint_sets_with_storage<> &zones,
                const std::set<nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>
                    &variable_set,
                const std::function<std::size_t(std::size_t, std::size_t,
                    nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>)>
                    &gate_var_address,
                std::size_t selector_index,
                std::size_t start_row_index,
                std::size_t end_row_index) {

                std::size_t last_row =
                    std::min<std::size_t>(end_row_index, assignment.selector_column_size(selector_index));
                for (std::size_t row = start_row_index; row < last_row; row++) {
                    if (assignment.selector(selector_index, row) != 0) {
                        for (const auto &variable : variable_set) {
                            zones.union_set(gate_var_address(start_row_index, row, variable),
                                        gate_var_address(start_row_index, row, *variable_set.begin()));
                        }
                    }
                }
            }

            template<typename BlueprintFieldType>
            bool check_set(
                const nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                boost::disjoint_sets_with_storage<> &zones,
                const std::set<nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>
                    &variable_set,
                const std::unordered_set<std::size_t> &expected_zones,
                const std::function<std::size_t(std::size_t, std::size_t,
                    nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>)>
                    &gate_var_address,
                std::size_t selector_index,
                std::size_t start_row_index,
                std::size_t end_row_index) {

                std::size_t last_row =
                    std::min<std::size_t>(end_row_index, assignment.selector_column_size(selector_index));
                for (std::size_t row = start_row_index; row < last_row; row++) {
                    if (assignment.selector(selector_index, row) != 0) {
                        for (const auto &variable : variable_set) {
                            const auto var_address = gate_var_address(start_row_index, row, variable);
                            if (expected_zones.count(zones.find_set(var_address)) == 0) {
                                return false;
                            }
                        }
                    }
                }
                return true;
            }

            template<typename BlueprintFieldType>
            boost::disjoint_sets_with_storage<> generate_connectedness_zones(
                const nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                const std::vector<std::reference_wrapper<nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                    &input_variables,
                const std::size_t start_row_index, std::size_t rows_amount) {

                using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                const std::size_t row_size = assignment.witnesses_amount() + assignment.constants_amount();
                const std::size_t ouptutless_var_amount = row_size * rows_amount;
                const std::size_t var_amount = ouptutless_var_amount + input_variables.size();
                boost::disjoint_sets_with_storage<> zones(var_amount);
                auto gate_var_address = [&row_size](std::size_t start_row_index, std::size_t row, const var &variable) {
                    if (variable.type == var::column_type::witness) {
                        return (row - start_row_index + variable.rotation) * row_size + variable.index;
                    } else {
                        // Constant
                        return (row - start_row_index + variable.rotation) * row_size + row_size - 1;
                    }
                };
                const std::size_t end_row_index = start_row_index + rows_amount;
                for (const auto &gate : bp.gates()) {
                    std::set<var> variable_set;
                    std::function<void(var)> variable_extractor = [&variable_set](var variable) {
                        variable_set.insert(variable);
                    };
                    nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                    for (const auto &constraint : gate.constraints) {
                        visitor.visit(constraint);
                    }
                    mark_set(assignment, zones, variable_set, gate_var_address, gate.selector_index,
                             start_row_index, end_row_index);
                }
                for (auto &lookup_gate : bp.lookup_gates()) {
                    std::set<var> variable_set;
                    std::function<void(var)> variable_extractor = [&variable_set](var variable) {
                        variable_set.insert(variable);
                    };
                    nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                    for (const auto &lookup_constraint : lookup_gate.constraints) {
                        for (const auto &lookup_input : lookup_constraint.lookup_input) {
                            visitor.visit(lookup_input);
                        }
                    }
                    mark_set(assignment, zones, variable_set, gate_var_address, lookup_gate.tag_index,
                             start_row_index, end_row_index);
                }
                for (auto &constraint : bp.copy_constraints()) {
                    zones.union_set(
                        copy_var_address<BlueprintFieldType>(
                            row_size, start_row_index, rows_amount, constraint.first),
                        copy_var_address<BlueprintFieldType>(
                            row_size, start_row_index, rows_amount, constraint.second));
                }
                return zones;
            }
        }    // namespace detail


        struct connectedness_check_type {
            enum class type {
                NONE,
                WEAK,
                STRONG
            } t;

            enum class island_type {
                NONE,
                ISLANDS
            } it;

            connectedness_check_type(type t) : t(t), it(island_type::ISLANDS) {}
            connectedness_check_type(type t, island_type it) : t(t), it(it) {}
        };

        // Checks if there are connected components which are separate from inputs/outputs
        // This should always be true for a correct component.
        // If this fails, either the component is wrong or the check is busted.
        template<typename BlueprintFieldType>
        bool check_islands(
            const nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
            const nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            boost::disjoint_sets_with_storage<> &zones,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &input_variables,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &output_variables,
            std::size_t start_row_index, std::size_t rows_amount) {

            using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::size_t row_size = assignment.witnesses_amount() + assignment.constants_amount();
            std::unordered_set<std::size_t> expected_zones;
            for (const auto &input_var : input_variables) {
                expected_zones.insert(zones.find_set(
                    detail::copy_var_address<BlueprintFieldType>(
                        row_size, start_row_index, rows_amount, input_var)));
            }
            for (const auto &output_var : output_variables) {
                expected_zones.insert(zones.find_set(
                    detail::copy_var_address<BlueprintFieldType>(
                        row_size, start_row_index, rows_amount, output_var)));
            }
            auto gate_var_address = [&row_size](std::size_t start_row_index, std::size_t row, const var &variable) {
                if (variable.type == var::column_type::witness) {
                    return (row - start_row_index + variable.rotation) * row_size + variable.index;
                } else {
                    // Constant
                    return (row - start_row_index + variable.rotation) * row_size + row_size - 1;
                }
            };
            const std::size_t end_row_index = start_row_index + rows_amount;
            for (const auto &gate : bp.gates()) {
                std::set<var> variable_set;
                std::function<void(var)> variable_extractor = [&variable_set](var variable) {
                    variable_set.insert(variable);
                };
                nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                for (const auto &constraint : gate.constraints) {
                    visitor.visit(constraint);
                }
                if (!detail::check_set(assignment, zones, variable_set, expected_zones, gate_var_address,
                                      gate.selector_index, start_row_index, end_row_index)) {
                    return false;
                }
            }
            for (auto &lookup_gate : bp.lookup_gates()) {
                std::set<var> variable_set;
                std::function<void(var)> variable_extractor = [&variable_set](var variable) {
                    variable_set.insert(variable);
                };
                nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                for (const auto &lookup_constraint : lookup_gate.constraints) {
                    for (const auto &lookup_input : lookup_constraint.lookup_input) {
                        visitor.visit(lookup_input);
                    }
                }
                if (!detail::check_set(assignment, zones, variable_set, expected_zones, gate_var_address,
                                      lookup_gate.tag_index, start_row_index, end_row_index)) {
                    return false;
                }
            }
            for (auto &constraint : bp.copy_constraints()) {
                const auto first_address =
                    detail::copy_var_address<BlueprintFieldType>(
                        row_size, start_row_index, rows_amount, constraint.first);
                const auto second_address =
                    detail::copy_var_address<BlueprintFieldType>(
                        row_size, start_row_index, rows_amount, constraint.second);
                if (expected_zones.count(zones.find_set(first_address)) == 0 ||
                    expected_zones.count(zones.find_set(second_address)) == 0) {
                    return false;
                }
            }
            return true;
        }

        // Ensure that output and input variables are connected via constraints.
        // This failing basically guarantees that the circuit is broken (or the check is).
        // There might exists rare components for which a lower level of connectedness is sufficient:
        // technically this checks that all inputs can affect all outputs.
        // For a weaker version, see check_weak_connectedness
        template<typename BlueprintFieldType>
        bool check_strong_connectedness(
            boost::disjoint_sets_with_storage<> &zones,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &input_variables,
            const std::vector<std::reference_wrapper<nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &output_variables,
            std::size_t row_size, std::size_t start_row_index, std::size_t rows_amount) {

            using detail::copy_var_address;
            std::size_t expected_zone = zones.find_set(
                copy_var_address<BlueprintFieldType>(
                    row_size, start_row_index, rows_amount, input_variables[0]));
            for (auto &variable : input_variables) {
                if (zones.find_set(copy_var_address<BlueprintFieldType>(
                                        row_size, start_row_index, rows_amount, variable)) != expected_zone) {
                    return false;
                }
            }
            for (auto &variable : output_variables) {
                if (zones.find_set(copy_var_address<BlueprintFieldType>(
                                        row_size, start_row_index, rows_amount, variable)) != expected_zone) {
                    return false;
                }
            }

            return true;
        }

        // Ensure that output and input variables are connected via constraints.
        // This failing basically guarantees that the circuit is broken (or the check is).
        // This version does not require that all inputs are connected to all outputs.
        // For a stronger version, see check_strong_connectedness
        template<typename BlueprintFieldType>
        bool check_weak_connectedness(
            boost::disjoint_sets_with_storage<> &zones,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &input_variables,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &output_variables,
            std::size_t row_size, std::size_t start_row_index, std::size_t rows_amount) {

            using detail::copy_var_address;
            std::set<std::size_t> expected_input_zones,
                                  expected_output_zones;
            // check that all outputs are connected to at least some input
            for (auto input_var : input_variables) {
                expected_input_zones.insert(
                    zones.find_set(
                        copy_var_address<BlueprintFieldType>(
                            row_size, start_row_index, rows_amount, input_var)));
            }
            for (auto &variable : output_variables) {
                if (expected_input_zones.count(
                        zones.find_set(copy_var_address<BlueprintFieldType>(
                                       row_size, start_row_index, rows_amount, variable))) == 0) {
                    return false;
                }
            }
            // check that all inputs are connected to at least some output
            for (auto output_var : output_variables) {
                expected_output_zones.insert(
                    zones.find_set(
                        copy_var_address<BlueprintFieldType>(
                            row_size, start_row_index, rows_amount, output_var)));
            }
            for (auto &variable : input_variables) {
                if (expected_output_zones.count(
                        zones.find_set(copy_var_address<BlueprintFieldType>(
                                       row_size, start_row_index, rows_amount, variable))) == 0) {
                    return false;
                }
            }

            return true;
        }

        template<typename BlueprintFieldType>
        bool check_connectedness(
            const nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
            const nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &input_variables,
            const std::vector<std::reference_wrapper<
                              nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>>
                &output_variables,
            std::size_t start_row_index, std::size_t rows_amount,
            connectedness_check_type type) {

            if (type.t == connectedness_check_type::type::NONE) {
                return true;
            }
            const std::size_t row_size = assignment.witnesses_amount() + assignment.constants_amount();
            auto zones = detail::generate_connectedness_zones(assignment, bp, input_variables,
                                                              start_row_index, rows_amount);
            bool check_result;
            switch(type.t) {
                case connectedness_check_type::type::NONE:
                    return true;
                case connectedness_check_type::type::WEAK:
                    check_result = check_weak_connectedness<BlueprintFieldType>(
                        zones, input_variables, output_variables, row_size, start_row_index, rows_amount);
                    break;
                case connectedness_check_type::type::STRONG:
                    check_result = check_strong_connectedness<BlueprintFieldType>(
                        zones, input_variables, output_variables, row_size, start_row_index, rows_amount);
                    break;
            }

            switch(type.it) {
                case connectedness_check_type::island_type::NONE:
                    return check_result;
                case connectedness_check_type::island_type::ISLANDS:
                    return check_result && check_islands<BlueprintFieldType>(
                        assignment, bp, zones, input_variables, output_variables, start_row_index, rows_amount);
            }
            return false;
        }
    }   // namespace blueprint
}    // namespace nil

#endif // CRYPTO3_BLUEPRINT_UTILS_PLONK_CONNECTEDNESS_CHECK_HPP
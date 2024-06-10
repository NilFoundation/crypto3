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

#ifndef CRYPTO3_BLUEPRINT_PLONK_COMPONENT_STRETCHER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_COMPONENT_STRETCHER_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/detail/huang_lu.hpp>
#include <nil/blueprint/utils/gate_mover.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/math/expression.hpp>

#include <boost/pending/disjoint_sets.hpp>
#include <list>
#include <unordered_map>
#include <sstream>
#include <type_traits>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename BlueprintFieldType>
            struct zoning_info {
                using constraint_type = nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = nil::crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;

                zoning_info() = default;
                zoning_info(std::size_t rows_amount_, std::size_t selector_amount_)
                    : rows_amount(rows_amount_), selector_amount(selector_amount_),
                      zones(rows_amount_ + selector_amount_ + 1),
                      constant_priority(rows_amount_, false) {}

                std::size_t rows_amount;
                std::size_t zones_amount;
                std::size_t selector_amount;
                // also stores gates as part of the zones structure
                // we want to move the same gates to the same columns to avoid gate duplication
                // after the gates, there is a special zone for the constant column
                boost::disjoint_sets_with_storage<> zones;
                std::unordered_map<std::size_t, std::size_t> zone_sizes;
                std::vector<bool> constant_priority;

                std::size_t selector_zone_idx(std::size_t selector_num) {
                    return rows_amount + selector_num;
                }

                std::size_t constant_zone_idx() {
                    return rows_amount + selector_amount;
                }

                void count_zones() {
                    std::set<std::size_t> seen;
                    for (std::size_t i = 0; i < rows_amount; i++) {
                        auto zone = zones.find_set(i);
                        seen.insert(zone);
                        if (zone_sizes.find(zone) != zone_sizes.end()) {
                            zone_sizes[zone]++;
                        } else {
                            zone_sizes[zone] = 1;
                        }
                    }
                    zones_amount = seen.size();
                }
            };
            // We want to know which parts of the circuit are connected to each other via gate constraints
            // And which can be rearranged with relative impunity
            // Additionally, we want to separate the zones by gate types inside the zones
            // Otherwise this would result in gate duplication, which is worse than doing nothing to the component
            template<typename BlueprintFieldType>
            zoning_info<BlueprintFieldType> generate_zones(
                const circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                std::size_t start_row_index,
                std::size_t rows_amount) {
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                std::map<std::size_t, std::array<bool, 6>> gate_range_map;
                for (const auto &gate : bp.gates()) {
                    gate_range_map[gate.selector_index] = {false, false, false, false, false, false};
                    std::array<bool, 6> &island = gate_range_map[gate.selector_index];
                    for (const auto &constraint : gate.constraints) {
                        std::set<var> variable_set;
                        std::function<void(var)> variable_extractor = [&variable_set](var variable) {
                            variable_set.insert(variable);
                        };
                        nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
                        visitor.visit(constraint);

                        for (const auto &variable : variable_set) {
                            BOOST_ASSERT(variable.rotation == -1 || variable.rotation == 0 || variable.rotation == 1);
                            if (variable.type == var::column_type::constant) {
                                island[variable.rotation + 4] = true;
                            } else {
                                island[variable.rotation + 1] = true;
                            }
                        }
                    }
                }

                zoning_info<BlueprintFieldType> zones(rows_amount, bp.num_gates());
                for (std::size_t i = start_row_index; i < start_row_index + rows_amount; i++) {
                    for (const auto &[selector, connection] : gate_range_map) {
                        if (i >= assignment.selector_column_size(selector) || assignment.selector(selector, i) == 0u) {
                            continue;
                        }
                        std::size_t row_idx = i - start_row_index;
                        if (connection[0]) {
                            zones.zones.union_set(row_idx - 1, row_idx);
                            zones.zones.union_set(row_idx - 1, zones.selector_zone_idx(selector));
                        }
                        if (connection[1]) {
                            zones.zones.union_set(row_idx, zones.selector_zone_idx(selector));
                        }
                        if (connection[2]) {
                            zones.zones.union_set(row_idx, row_idx + 1);
                            zones.zones.union_set(row_idx + 1, zones.selector_zone_idx(selector));
                        }
                        // The proper way of dealing with constants requires changing the NP-hard problem being solved
                        // This is a hack
                        if (connection[3]) {
                            zones.zones.union_set(row_idx - 1, zones.constant_zone_idx());
                            zones.constant_priority[row_idx - 1] = true;
                        }
                        if (connection[4]) {
                            zones.zones.union_set(row_idx, zones.constant_zone_idx());
                            zones.constant_priority[row_idx] = true;
                        }
                        if (connection[5]) {
                            zones.zones.union_set(row_idx + 1, zones.constant_zone_idx());
                            zones.constant_priority[row_idx + 1] = true;
                        }
                    }
                }
                zones.count_zones();
                return zones;
            }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename ComponentType>
            class component_stretcher {
            public:
                typedef typename ComponentType::input_type input_type;
                typedef typename ComponentType::result_type result_type;
                typedef zoning_info<BlueprintFieldType> zone_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using gate_type = typename nil::crypto3::zk::snark::plonk_gate<BlueprintFieldType,
                                                    nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>>;

                // overloading this because this isn't a proper component (not in the inheritance hierarchy)
                std::size_t witness_amount() const {
                    return stretched_witness_amount;
                }

                ComponentType &component;
                const std::size_t old_witness_amount;
                const std::size_t stretched_witness_amount;

                mutable std::size_t stretch_coeff;
                mutable zone_type zones;
                mutable std::unordered_map<std::size_t, std::size_t> zone_mapping;
                mutable std::unordered_map<std::size_t, std::size_t> gate_mapping;
                mutable std::vector<std::size_t> line_mapping;
                // Hack to avoid changing the NP-hard problem being solved to properly include the constant column
                mutable std::unordered_map<std::size_t, std::size_t> constant_remapping;
                mutable std::size_t rows_amount;
                mutable bool remapping_computed = false;

                void compute_remapping(
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                        std::size_t old_witness_amount,
                        const input_type &instance_input) const {
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> tmp_circuit;
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> tmp_assignment(
                        assignment.witnesses_amount(), assignment.public_inputs_amount(),
                        assignment.constants_amount(), assignment.selectors_amount()
                    );
                    auto converted_input = input_type_converter<ComponentType>::convert(instance_input, assignment,
                                                                                        tmp_assignment);
                    generate_circuit(this->component, tmp_circuit, tmp_assignment, converted_input, 0);
                    generate_assignments(this->component, tmp_assignment, converted_input, 0);
                    zones = generate_zones(tmp_circuit, tmp_assignment, 0, this->component.rows_amount);

                    // Computing the optimal packing is NP-hard.
                    // See [https://en.wikipedia.org/wiki/Identical-machines_scheduling].
                    // We use an approximation algorithm.
                    std::list<std::pair<std::size_t, std::size_t>> zone_sizes_for_packing;
                    for (auto [zone, size] : zones.zone_sizes) {
                        zone_sizes_for_packing.push_back({zone, size});
                    }
                    zone_mapping = detail::huang_lu(zone_sizes_for_packing, stretch_coeff);

                    std::vector<std::size_t> zone_rows(zones.zone_sizes.size(), 0);
                    line_mapping.resize(this->component.rows_amount);
                    std::vector<bool> constant_assigned(this->component.rows_amount, false);
                    for (std::size_t i = 0; i < this->component.rows_amount; i++) {
                        auto zone = zone_mapping[zones.zones.find_set(i)];
                        line_mapping[i] = zone_rows[zone];
                        if (zones.constant_priority[i]) {
                            constant_assigned[line_mapping[i]] = true;
                        }
                        zone_rows[zone]++;
                    }

                    // Hack to deal with constants
                    std::set<var> constrained_constant_vars;
                    for (auto &[first_var, second_var] : tmp_circuit.copy_constraints()) {
                        for (auto &curr_var : {std::ref(first_var), std::ref(second_var)}) {
                            if (curr_var.get().type != var::column_type::constant) {
                                continue;
                            }
                            constrained_constant_vars.insert(curr_var);
                        }
                    }
                    std::size_t first_unassigned_const = 0;
                    while (constant_assigned[first_unassigned_const]) {
                        first_unassigned_const++;
                    }
                    for (auto curr_var : constrained_constant_vars) {
                        std::size_t new_rotation = line_mapping[curr_var.rotation];
                        if (constant_assigned[new_rotation]) {
                            // Need to remap
                            constant_remapping[curr_var.rotation] = first_unassigned_const;
                            constant_assigned[first_unassigned_const] = true;
                            while (constant_assigned[first_unassigned_const]) {
                                first_unassigned_const++;
                            }
                        } else {
                            // We rely on default remapping
                             constant_remapping[curr_var.rotation] = new_rotation;
                            constant_assigned[new_rotation] = true;
                            if (first_unassigned_const == new_rotation) {
                                while (constant_assigned[first_unassigned_const]) {
                                    first_unassigned_const++;
                                }
                            }
                        }
                    }
                    this->rows_amount = std::max_element(zones.zone_sizes.begin(), zones.zone_sizes.end(),
                                                         [](auto a, auto b) { return a.second < b.second; })->second;
                    this->remapping_computed = true;
                }

                var move_var(const var &old, std::int32_t new_rotation, const input_type &input) const {
                    var new_var;
                    switch (old.type) {
                        case var::column_type::constant:
                            // Assumes a single constant column
                            new_var = var(
                                old.index,
                                new_rotation,
                                old.relative,
                                var::column_type::constant);
                            break;
                        case var::column_type::public_input:
                            // public input is actually the original input variables
                            new_var = input_type_converter<ComponentType>::deconvert_var(input, old);
                            break;
                        case var::column_type::witness:
                            BOOST_ASSERT_MSG(
                                old.relative == false,
                                "We should not move relative variables with move_var, use move_gate_var for gate variables. Copy constraints should be absolute.");
                            new_var = var(zone_mapping[zones.zones.find_set(old.rotation)] * old_witness_amount + old.index,
                                          new_rotation,
                                          old.relative,
                                          var::column_type::witness);
                            break;
                        case var::column_type::selector:
                            BOOST_ASSERT_MSG(false, "Selectors should be moved while moving gates.");
                            break;
                        case var::column_type::uninitialized:
                            BOOST_ASSERT_MSG(false, "Uninitialized variable should not be moved.");
                            break;
                    }
                    return new_var;
                }

                var move_gate_var(var old, std::size_t selector) const {
                    var new_var;
                    switch (old.type) {
                        case var::column_type::public_input:
                            BOOST_ASSERT_MSG(false, "Public input should not belong to a gate.");
                            break;
                        case var::column_type::constant:
                            // Assumes only a single constant column
                            new_var = var(
                                old.index,
                                old.rotation,
                                old.relative,
                                var::column_type::constant);
                            break;
                        case var::column_type::witness:
                            new_var = var(
                                zone_mapping[zones.zones.find_set(this->component.rows_amount + selector)] * old_witness_amount +
                                    old.index,
                                old.rotation,
                                old.relative,
                                var::column_type::witness);
                            break;
                        case var::column_type::selector:
                            BOOST_ASSERT_MSG(false, "Selector columns should not be inside gates.");
                            break;
                        case var::column_type::uninitialized:
                            BOOST_ASSERT_MSG(false, "Uninitialized variable should not be moved.");
                            break;
                    }
                    return new_var;
                }

                void move_circuit(
                    const circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &tmp_circuit,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &tmp_assignment,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const input_type &instance_input,
                    std::size_t start_row_index) const {
                    // Need to do multiple things here:
                    // 1) Move gates, including properly generating them
                    for (auto gate : tmp_circuit.gates()) {
                        std::vector<nil::crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> new_constraints;
                        gate_mover gate_displacer = gate_mover<BlueprintFieldType>(
                            std::bind(&component_stretcher::move_gate_var,
                                      this, std::placeholders::_1, gate.selector_index));
                        for (auto constraint: gate.constraints) {
                            auto new_constraint = gate_displacer.visit(constraint);
                            new_constraints.push_back(new_constraint);
                        }
                        gate_mapping[gate.selector_index] = bp.add_gate(new_constraints);
                    }
                    // 2) Move selectors.
                    for (std::size_t i = 0; i < this->component.rows_amount; i++) {
                        for (std::size_t s = 0; s < tmp_assignment.selectors_amount(); s++) {
                            if (i < tmp_assignment.selector_column_size(s) && tmp_assignment.selector(s, i) != 0) {
                                assignment.selector(gate_mapping[s], start_row_index + line_mapping[i]) =
                                    tmp_assignment.selector(s, i);
                            }
                        }
                    }
                    // 3) Move constants
                    if (tmp_assignment.constants_amount() > 0 && tmp_assignment.constant_column_size(0) > 0) {
                        for (std::size_t i = 0; i < this->component.rows_amount; i++) {
                            for (std::size_t c = 0; c < tmp_assignment.constants_amount(); c++) {
                                if (i >= tmp_assignment.constant_column_size(c)) {
                                    continue;
                                }
                                if (constant_remapping.find(i) != constant_remapping.end()) {
                                    assignment.constant(c, start_row_index + constant_remapping[i]) =
                                        tmp_assignment.constant(c, i);
                                } else if (zones.constant_priority[i]) {
                                    assignment.constant(c, start_row_index + line_mapping[i]) =
                                        tmp_assignment.constant(c, i);
                                }
                            }
                        }
                    }
                    // 4) Move copy constraints
                    for (auto constraint : tmp_circuit.copy_constraints()) {
                        var new_first, new_second;
                        for (auto &[new_var, old_var] :
                                              {std::make_pair(std::ref(new_first), constraint.first),
                                               std::make_pair(std::ref(new_second), constraint.second)}) {
                            if (old_var.type == var::column_type::constant &&
                                constant_remapping.find(old_var.rotation) != constant_remapping.end()) {
                                new_var = move_var(
                                    old_var,
                                    start_row_index + constant_remapping[old_var.rotation],
                                    instance_input);
                            } else {
                                new_var = move_var(
                                    old_var,
                                    start_row_index + line_mapping[old_var.rotation],
                                    instance_input);
                            }
                        }
                        if (constraint.first.type == var::column_type::constant ||
                            constraint.second.type == var::column_type::constant) {
                        }
                        nil::crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>
                            new_constraint(new_first, new_second);
                        bp.add_copy_constraint(new_constraint);
                    }
                }

                void move_assignment(
                    const component_stretcher<BlueprintFieldType, ComponentType>
                        &component,
                    const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &tmp_assignment,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    std::size_t start_row_index) const {

                    for (std::size_t i = 0; i < this->component.rows_amount; i++) {
                        std::size_t zone = zone_mapping[zones.zones.find_set(i)];
                        for (std::size_t w = 0; w < old_witness_amount; w++) {
                            if (i < tmp_assignment.witness_column_size(w)) {
                                assignment.witness(w + old_witness_amount * zone, start_row_index + line_mapping[i]) =
                                    tmp_assignment.witness(w, i);
                            }
                        }
                    }
                    // Public input column is NOT moved
                    // Selectors and constants are moved in move_circuit,
                    // because generate_assignments doesn't create them
                }

                component_stretcher(ComponentType &component_,
                                   std::size_t old_witness_amount_,
                                   std::size_t stretched_witness_amount_)
                    : component(component_), old_witness_amount(old_witness_amount_),
                      stretched_witness_amount(stretched_witness_amount_),
                      stretch_coeff(stretched_witness_amount_ / old_witness_amount_) {}
            };

            template<typename BlueprintFieldType, typename ComponentType>
            typename ComponentType::result_type generate_circuit(
                const component_stretcher<BlueprintFieldType, ComponentType>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename component_stretcher<BlueprintFieldType,
                                                         ComponentType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                if (!component.remapping_computed) {
                    component.compute_remapping(assignment, component.witness_amount(), instance_input);
                }
                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    tmp_assignment(assignment.witnesses_amount(), assignment.public_inputs_amount(),
                                   assignment.constants_amount(), assignment.selectors_amount());
                circuit<crypto3::zk::snark::plonk_constraint_system<
                    BlueprintFieldType>> tmp_circuit;

                auto result = generate_circuit(
                    component.component, tmp_circuit, tmp_assignment, instance_input, 0);
                component.move_circuit(tmp_circuit, tmp_assignment, bp, assignment,
                                       instance_input, start_row_index);
                return result_type_converter<ComponentType>::convert(component, result, instance_input,
                                                                     start_row_index);
            }

            template<typename BlueprintFieldType, typename ComponentType>
            typename ComponentType::result_type generate_assignments(
                const component_stretcher<BlueprintFieldType, ComponentType>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename component_stretcher<BlueprintFieldType, ComponentType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                if (!component.remapping_computed) {
                    component.compute_remapping(assignment, component.witness_amount(),instance_input);
                }

                nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<
                    BlueprintFieldType>> tmp_assignment(
                        assignment.witnesses_amount(), assignment.public_inputs_amount(),
                        assignment.constants_amount(), assignment.selectors_amount());
                circuit<crypto3::zk::snark::plonk_constraint_system<
                    BlueprintFieldType>> tmp_circuit;

                auto converted_input = input_type_converter<ComponentType>::convert(instance_input, assignment,
                                                                                    tmp_assignment);
                // We need to generate a circuit here, because the constants are generated in generate_circuit.
                // The assignment might rely on the generated constants.
                generate_circuit(
                    component.component, tmp_circuit, tmp_assignment, converted_input, 0);
                auto result = generate_assignments(
                    component.component, tmp_assignment, converted_input, 0);
                component.move_assignment(component, tmp_assignment, assignment, start_row_index);

                return result_type_converter<ComponentType>::convert(component, result, instance_input,
                                                                     start_row_index);
            }

            template<typename BlueprintFieldType, typename ComponentType>
            struct is_component_stretcher : std::false_type {};

            template<typename BlueprintFieldType, typename ComponentType>
            struct is_component_stretcher<
                BlueprintFieldType,
                component_stretcher<BlueprintFieldType, ComponentType>>
                    : std::true_type {};

        } // namespace components
    }     // namespace blueprint
}   // namespace nil

#endif   // CRYPTO3_BLUEPRINT_PLONK_COMPONENT_STRETCHER_HPP

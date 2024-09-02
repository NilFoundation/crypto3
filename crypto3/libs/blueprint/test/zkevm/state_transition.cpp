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

#define BOOST_TEST_MODULE zkevm_state_transition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>

#include <nil/blueprint/zkevm/state.hpp>
#include <nil/blueprint/zkevm/zkevm_circuit.hpp>

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

template<typename BlueprintFieldType>
void fill_empty_state(zkevm_state<BlueprintFieldType>& state) {
    using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    std::size_t witness_index = 0;
    #define X(name) state.name.selector = witness_index++; \
        state.name.type = var::column_type::witness; \
        state.name.value = 0;
    zkevm_STATE_LIST_FOR_TRANSITIONS(X)
    #undef X

    state.step_selection.selector = witness_index++;
    state.rows_until_next_op.selector = witness_index++;
    state.rows_until_next_op_inv.selector = witness_index++;

    state.step_selection.type = var::column_type::witness;
    state.rows_until_next_op.type = var::column_type::witness;
    state.rows_until_next_op_inv.type = var::column_type::witness;

    state.step_selection.value = 0;
    state.rows_until_next_op.value = 0;
    state.rows_until_next_op_inv.value = 0;
}

BOOST_AUTO_TEST_SUITE(zkevm_state_transition_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_state_transition_basic_test) {
    using field_type = fields::goldilocks64;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using state_type = zkevm_state<field_type>;
    assignment_type assignment(20, 0, 0, 1);
    circuit_type circuit;

    std::size_t row = 0;
    state_type state;
    fill_empty_state(state);
    zkevm_state_transition transition;
    auto constraints = generate_transition_constraints(state, transition);
    auto selector = circuit.add_gate(constraints);
    assignment.enable_selector(selector, row);
    state.assign_state(assignment, row++);
    state.pc.value += 1;
    state.assign_state(assignment, row++);

    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
    state.pc.value = 0;
    state.assign_state(assignment, row - 1);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == false);
}

BOOST_AUTO_TEST_CASE(zkevm_state_transition_other_test) {
    using field_type = fields::goldilocks64;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using state_type = zkevm_state<field_type>;
    assignment_type assignment(20, 0, 0, 1);
    circuit_type circuit;

    std::size_t row = 0;
    state_type state;
    fill_empty_state(state);
    zkevm_state_transition transition;
    transition.curr_gas.t = transition_type::NEW_VALUE;
    transition.curr_gas.value = 100;
    auto constraints = generate_transition_constraints(state, transition);
    auto selector = circuit.add_gate(constraints);
    assignment.enable_selector(selector, row);
    state.assign_state(assignment, row++);
    state.pc.value += 1;
    state.curr_gas.value = 100;
    state.assign_state(assignment, row++);

    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
    state.curr_gas.value = 0;
    state.assign_state(assignment, row - 1);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == false);
    state.curr_gas.value = -1;
    state.assign_state(assignment, row - 1);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == false);
}

BOOST_AUTO_TEST_SUITE_END()

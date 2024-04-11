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

#define BOOST_TEST_MODULE blueprint_component_batch_test

#include <boost/test/unit_test.hpp>
#include <boost/random.hpp>

#include <set>
#include <iostream>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/component_batch.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division_or_zero.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication_by_constant.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/swap.hpp>

using namespace nil::blueprint;
using namespace nil;

template<typename FieldType>
struct compare_copy_constraints {
    bool operator()(const crypto3::zk::snark::plonk_copy_constraint<FieldType> &lhs,
                    const crypto3::zk::snark::plonk_copy_constraint<FieldType> &rhs) const {
        crypto3::zk::snark::plonk_copy_constraint<FieldType> norm_lhs =
            lhs.first < lhs.second ? lhs : crypto3::zk::snark::plonk_copy_constraint<FieldType>(lhs.second, lhs.first);
        crypto3::zk::snark::plonk_copy_constraint<FieldType> norm_rhs =
            rhs.first < rhs.second ? rhs : crypto3::zk::snark::plonk_copy_constraint<FieldType>(rhs.second, rhs.first);
        return norm_lhs.first < norm_rhs.first || (norm_lhs.first == norm_rhs.first && norm_lhs.second < norm_rhs.second);
    }
};

template<typename FieldType>
bool compare_copy_constraint_vectors(const std::vector<crypto3::zk::snark::plonk_copy_constraint<FieldType>> &lhs,
                                     const std::vector<crypto3::zk::snark::plonk_copy_constraint<FieldType>> &rhs) {
    std::set<crypto3::zk::snark::plonk_copy_constraint<FieldType>, compare_copy_constraints<FieldType>>
        lhs_set, rhs_set;

    for( const auto &c: lhs ) {
        lhs_set.insert(c);
    }
    for( const auto &c: rhs ) {
        rhs_set.insert(c);
    }

    if (lhs_set.size() != rhs_set.size() ) {
        return false;
    }
    return lhs_set == rhs_set;
}

template<typename FieldType>
struct public_input_var_maker {
    using var = crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;
    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<FieldType>>;
    assignment_type& assignment;
    nil::crypto3::random::algebraic_engine<FieldType> generate_random;
    boost::random::uniform_int_distribution<std::size_t> bool_dist{0, 1};
    boost::random::mt19937 seed_seq{1444};
    std::size_t curr_idx = 0;

    public_input_var_maker(assignment_type& assignment_) : assignment(assignment_) {
        generate_random.seed(seed_seq);
    }

    var operator()() {
        assignment.public_input(0, curr_idx) = generate_random();
        return var(0, curr_idx++, false, var::column_type::public_input);
    }

    var binary_var() {
        assignment.public_input(0, curr_idx) = bool_dist(seed_seq);
        return var(0, curr_idx++, false, var::column_type::public_input);
    }
};

BOOST_AUTO_TEST_SUITE(blueprint_component_batch_test_suite)

BOOST_AUTO_TEST_CASE(component_batch_basic_test) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = typename curve_type::scalar_field_type;

    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using circuit_type = circuit<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;
    using constraint_type = crypto3::zk::snark::plonk_constraint<field_type>;
    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<field_type>;

    assignment_type assignment(14, 1, 0, 1);
    circuit_type circuit;
    public_input_var_maker<field_type> public_input_var_maker(assignment);

    using component_type = components::multiplication<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;
    assignment.add_input_to_batch_assignment<component_type>({public_input_var_maker(), public_input_var_maker()});
    assignment.add_input_to_batch_assignment<component_type>({public_input_var_maker(), public_input_var_maker()});
    std::size_t row = assignment.finalize_component_batches(circuit, 0);
    BOOST_CHECK_EQUAL(row, 1);
    BOOST_CHECK_EQUAL(circuit.gates().size(), 1);
    const auto &gate = circuit.gates()[0];
    BOOST_CHECK_EQUAL(gate.constraints.size(), 4);
    std::array<constraint_type, 4> expected_constraints = {
        var(0, 0) * var(1, 0) - var(2, 0),
        var(3, 0) * var(4, 0) - var(5, 0),
        var(6, 0) * var(7, 0) - var(8, 0),
        var(9, 0) * var(10, 0) - var(11, 0)
    };
    for (std::size_t i = 0; i < gate.constraints.size(); ++i) {
        BOOST_CHECK_EQUAL(gate.constraints[i], expected_constraints[i]);
    }
    const std::vector<copy_constraint_type> expected_copy_constraints = {
        {var(0, 0, false, var::column_type::public_input), var(0, 0, false, var::column_type::witness)},
        {var(1, 0, false, var::column_type::witness), var(0, 1, false, var::column_type::public_input)},
        {var(0, 2, false, var::column_type::public_input), var(3, 0, false, var::column_type::witness)},
        {var(4, 0, false, var::column_type::witness), var(0, 3, false, var::column_type::public_input)}
    };
    BOOST_ASSERT(compare_copy_constraint_vectors<field_type>(circuit.copy_constraints(), expected_copy_constraints));

    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
}

BOOST_AUTO_TEST_CASE(component_batch_continuation_test) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = typename curve_type::scalar_field_type;

    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using circuit_type = circuit<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;
    using constraint_type = crypto3::zk::snark::plonk_constraint<field_type>;
    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<field_type>;

    assignment_type assignment(15, 1, 0, 2);
    circuit_type circuit;
    public_input_var_maker<field_type> public_input_var_maker(assignment);

    using component_type = components::multiplication<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;
    auto first_result = assignment.add_input_to_batch_assignment<component_type>({public_input_var_maker(), public_input_var_maker()});
    auto second_result = assignment.add_input_to_batch_assignment<component_type>({public_input_var_maker(), public_input_var_maker()});
    assignment.add_input_to_batch_assignment<component_type>({public_input_var_maker(), public_input_var_maker()});
    auto third_result = assignment.add_input_to_batch_assignment<component_type>({public_input_var_maker(), public_input_var_maker()});
    auto fourth_result = assignment.add_input_to_batch_assignment<component_type>({first_result.output, second_result.output});
    using addition_type = components::addition<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;
    std::size_t row = 0;
    addition_type add_component({0, 1, 2}, {}, {});
    auto addition_result = generate_assignments(add_component, assignment, {third_result.output, fourth_result.output}, row);
    generate_circuit(add_component, circuit, assignment, {third_result.output, fourth_result.output}, row++);
    auto fifth_result = assignment.add_input_to_batch_assignment<component_type>({addition_result.output, public_input_var_maker()});
    generate_assignments(add_component, assignment, {addition_result.output, fifth_result.output}, row);
    generate_circuit(add_component, circuit, assignment, {addition_result.output, fifth_result.output}, row++);
    row = assignment.finalize_component_batches(circuit, row);
    BOOST_CHECK_EQUAL(row, 4);
    BOOST_CHECK_EQUAL(circuit.gates().size(), 2);
    const auto &gate = circuit.gates()[1];
    BOOST_CHECK_EQUAL(gate.constraints.size(), 5);
    std::array<constraint_type, 5> expected_constraints = {
        var(0, 0) * var(1, 0) - var(2, 0),
        var(3, 0) * var(4, 0) - var(5, 0),
        var(6, 0) * var(7, 0) - var(8, 0),
        var(9, 0) * var(10, 0) - var(11, 0),
        var(12, 0) * var(13, 0) - var(14, 0)
    };
    for (std::size_t i = 0; i < gate.constraints.size(); ++i) {
        BOOST_CHECK_EQUAL(gate.constraints[i], expected_constraints[i]);
    }
    const std::vector<copy_constraint_type> expected_copy_constraints = {
        {var(11, 2, false, var::column_type::witness), var(0, 0, false, var::column_type::witness)},
        {var(1, 0, false, var::column_type::witness), var(2, 3, false, var::column_type::witness)},
        {var(2, 0, false, var::column_type::witness), var(0, 1, false, var::column_type::witness)},
        {var(1, 1, false, var::column_type::witness), var(14, 2, false, var::column_type::witness)},
        {var(0, 0, false, var::column_type::public_input), var(0, 2, false, var::column_type::witness)},
        {var(1, 2, false, var::column_type::witness), var(0, 1, false, var::column_type::public_input)},
        {var(0, 2, false, var::column_type::public_input), var(3, 2, false, var::column_type::witness)},
        {var(4, 2, false, var::column_type::witness), var(0, 3, false, var::column_type::public_input)},
        {var(0, 4, false, var::column_type::public_input), var(6, 2, false, var::column_type::witness)},
        {var(7, 2, false, var::column_type::witness), var(0, 5, false, var::column_type::public_input)},
        {var(0, 6, false, var::column_type::public_input), var(9, 2, false, var::column_type::witness)},
        {var(10, 2, false, var::column_type::witness), var(0, 7, false, var::column_type::public_input)},
        {var(2, 0, false, var::column_type::witness), var(12, 2, false, var::column_type::witness)},
        {var(13, 2, false, var::column_type::witness), var(0, 8, false, var::column_type::public_input)},
        {var(2, 2, false, var::column_type::witness), var(0, 3, false, var::column_type::witness)},
        {var(1, 3, false, var::column_type::witness), var(5, 2, false, var::column_type::witness)}
    };

    BOOST_ASSERT(compare_copy_constraint_vectors<field_type>(circuit.copy_constraints(), expected_copy_constraints));

    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
}

BOOST_AUTO_TEST_CASE(component_batch_multibatch_test) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = typename curve_type::scalar_field_type;

    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using circuit_type = circuit<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;
    using constraint_type = crypto3::zk::snark::plonk_constraint<field_type>;
    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<field_type>;

    assignment_type assignment(15, 1, 0, 3);
    circuit_type circuit;
    public_input_var_maker<field_type> public_input_var_maker(assignment);

    using mul_component_type = components::multiplication<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;
    using add_component_type = components::addition<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;
    using div_or_zero_component_type = components::division_or_zero<ArithmetizationType, field_type>;
    auto mul_result = assignment.add_input_to_batch_assignment<mul_component_type>(
        {public_input_var_maker(), public_input_var_maker()});
    auto add_result = assignment.add_input_to_batch_assignment<add_component_type>({mul_result.output, public_input_var_maker()});
    auto mul_result_2 = assignment.add_input_to_batch_assignment<mul_component_type>({add_result.output, mul_result.output});
    assignment.add_input_to_batch_assignment<mul_component_type>({public_input_var_maker(), public_input_var_maker()});
    div_or_zero_component_type div_or_zero_component({0, 1, 2, 3, 4}, {}, {});
    var div_or_zero_var = public_input_var_maker();
    auto div_or_zero_res = generate_assignments(
        div_or_zero_component, assignment, {mul_result_2.output, div_or_zero_var}, 0);
    generate_circuit(div_or_zero_component, circuit, assignment, {mul_result_2.output, div_or_zero_var}, 0);
    assignment.add_input_to_batch_assignment<mul_component_type>({div_or_zero_res.output, public_input_var_maker()});
    assignment.add_input_to_batch_assignment<mul_component_type>({public_input_var_maker(), public_input_var_maker()});
    assignment.add_input_to_batch_assignment<add_component_type>({add_result.output, mul_result.output});
    // duplicates, should not count!
    for (std::size_t i = 0; i < 5; i++) {
        assignment.add_input_to_batch_assignment<add_component_type>({add_result.output, mul_result.output});
    }
    // not duplicates, should count
    for (std::size_t i = 0; i < 5; i++) {
        assignment.add_input_to_batch_assignment<mul_component_type>({public_input_var_maker(), public_input_var_maker()});
    }
    std::size_t row = assignment.finalize_component_batches(circuit, 1);
    BOOST_CHECK_EQUAL(row, 4);

    BOOST_CHECK_EQUAL(circuit.gates().size(), 3);
    const auto &gate_1 = circuit.gates()[1];
    BOOST_CHECK_EQUAL(gate_1.constraints.size(), 5);
    const std::array<constraint_type, 5> expected_constraints_mul = {
        var(0, 0) * var(1, 0) - var(2, 0),
        var(3, 0) * var(4, 0) - var(5, 0),
        var(6, 0) * var(7, 0) - var(8, 0),
        var(9, 0) * var(10, 0) - var(11, 0),
        var(12, 0) * var(13, 0) - var(14, 0)
    };
    const std::array<constraint_type, 5> expected_constraints_add = {
        var(0, 0) + var(1, 0) - var(2, 0),
        var(3, 0) + var(4, 0) - var(5, 0),
        var(6, 0) + var(7, 0) - var(8, 0),
        var(9, 0) + var(10, 0) - var(11, 0),
        var(12, 0) + var(13, 0) - var(14, 0)
    };
    if (gate_1.constraints[0] == var(0, 0) * var(1, 0) - var(2, 0)) {
        for (std::size_t i = 0; i < gate_1.constraints.size(); ++i) {
            BOOST_CHECK_EQUAL(gate_1.constraints[i], expected_constraints_mul[i]);
        }
    } else {
        for (std::size_t i = 0; i < gate_1.constraints.size(); ++i) {
            BOOST_CHECK_EQUAL(gate_1.constraints[i], expected_constraints_add[i]);
        }
    }
    const auto &gate_2 = circuit.gates()[2];
    BOOST_CHECK_EQUAL(gate_1.constraints.size(), 5);
    if (gate_2.constraints[0] == var(0, 0) * var(1, 0) - var(2, 0)) {
        for (std::size_t i = 0; i < gate_2.constraints.size(); ++i) {
            BOOST_CHECK_EQUAL(gate_2.constraints[i], expected_constraints_mul[i]);
        }
    } else {
        for (std::size_t i = 0; i < gate_2.constraints.size(); ++i) {
            BOOST_CHECK_EQUAL(gate_2.constraints[i], expected_constraints_add[i]);
        }
    }
    BOOST_ASSERT((gate_1.constraints[0] == expected_constraints_mul[0] &&
                  gate_2.constraints[0] == expected_constraints_add[0]) ||
                 (gate_1.constraints[0] == expected_constraints_add[0] &&
                  gate_2.constraints[0] == expected_constraints_mul[0]));

    const std::vector<copy_constraint_type> expected_copy_constraints = {
        {var(14, 2, false, var::column_type::witness), var(0, 0, false, var::column_type::witness)},
        {var(1, 0, false, var::column_type::witness), var(0, 5, false, var::column_type::public_input)},
        {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::witness)},
        {var(1, 1, false, var::column_type::witness), var(0, 1, false, var::column_type::public_input)},
        {var(0, 3, false, var::column_type::public_input), var(3, 1, false, var::column_type::witness)},
        {var(4, 1, false, var::column_type::witness), var(0, 4, false, var::column_type::public_input)},
        {var(0, 7, false, var::column_type::public_input), var(6, 1, false, var::column_type::witness)},
        {var(7, 1, false, var::column_type::witness), var(0, 8, false, var::column_type::public_input)},
        {var(0, 9, false, var::column_type::public_input), var(9, 1, false, var::column_type::witness)},
        {var(10, 1, false, var::column_type::witness), var(0, 10, false, var::column_type::public_input)},
        {var(0, 11, false, var::column_type::public_input), var(12, 1, false, var::column_type::witness)},
        {var(13, 1, false, var::column_type::witness), var(0, 12, false, var::column_type::public_input)},
        {var(0, 13, false, var::column_type::public_input), var(0, 2, false, var::column_type::witness)},
        {var(1, 2, false, var::column_type::witness), var(0, 14, false, var::column_type::public_input)},
        {var(0, 15, false, var::column_type::public_input), var(3, 2, false, var::column_type::witness)},
        {var(4, 2, false, var::column_type::witness), var(0, 16, false, var::column_type::public_input)},
        {var(0, 17, false, var::column_type::public_input), var(6, 2, false, var::column_type::witness)},
        {var(7, 2, false, var::column_type::witness), var(0, 18, false, var::column_type::public_input)},
        {var(2, 0, false, var::column_type::witness), var(9, 2, false, var::column_type::witness)},
        {var(10, 2, false, var::column_type::witness), var(0, 6, false, var::column_type::public_input)},
        {var(2, 3, false, var::column_type::witness), var(12, 2, false, var::column_type::witness)},
        {var(13, 2, false, var::column_type::witness), var(2, 1, false, var::column_type::witness)},
        {var(2, 1, false, var::column_type::witness), var(0, 3, false, var::column_type::witness)},
        {var(1, 3, false, var::column_type::witness), var(0, 2, false, var::column_type::public_input)},
        {var(2, 3, false, var::column_type::witness), var(3, 3, false, var::column_type::witness)},
        {var(4, 3, false, var::column_type::witness), var(2, 1, false, var::column_type::witness)}
    };

    BOOST_ASSERT(compare_copy_constraint_vectors<field_type>(circuit.copy_constraints(), expected_copy_constraints));

    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
}

BOOST_AUTO_TEST_CASE(component_batch_const_batch_test) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = typename curve_type::scalar_field_type;

    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using circuit_type = circuit<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;
    using constraint_type = crypto3::zk::snark::plonk_constraint<field_type>;
    using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<field_type>;
    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<field_type>;

    assignment_type assignment(15, 1, 1, 3);
    circuit_type circuit;
    public_input_var_maker<field_type> public_input_var_maker(assignment);

    using multiplication_type = components::multiplication<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;
    using mul_by_constant_type = components::mul_by_constant<ArithmetizationType, field_type>;

    mul_by_constant_type mul_by_constant_component({0, 1, 2}, {0}, {}, 1444);
    std::size_t row = 0;
    var mul_by_constant_input = public_input_var_maker();
    auto mul_by_const_result = generate_assignments(
        mul_by_constant_component, assignment, {mul_by_constant_input}, row);
    generate_circuit(mul_by_constant_component, circuit, assignment, {mul_by_constant_input}, row++);
    lookup_constraint_type lookup_constraint;
    lookup_constraint.table_id = 0;
    lookup_constraint.lookup_input.push_back(constraint_type({var(0, 1, true, var::column_type::constant)}));
    std::size_t lookup_selector = circuit.add_lookup_gate(lookup_constraint);
    assignment.enable_selector(lookup_selector, row++);
    // filling the constants is required to resize the column
    assignment.constant(0, row) = 1445;
    assignment.enable_selector(lookup_selector, row++);
    assignment.constant(0, row) = 1446;
    auto mul_result = assignment.add_input_to_batch_assignment<multiplication_type>(
        {assignment.add_batch_constant_variable(1), assignment.add_batch_constant_variable(2)});
    // have to check lookup functionality manually
    assignment.add_input_to_batch_assignment<multiplication_type>({public_input_var_maker(), mul_result.output});
    assignment.add_input_to_batch_assignment<multiplication_type>({mul_by_const_result.output, public_input_var_maker()});
    assignment.finalize_component_batches(circuit, row);
    assignment.finalize_constant_batches(circuit, 0);

    // duplicates; should not count!
    for (std::size_t i = 0; i < 10; i++) {
        assignment.add_batch_constant_variable(2);
    }

    BOOST_ASSERT(assignment.constant(0, 0) == 1444);
    BOOST_ASSERT(assignment.constant(0, 1) == 1);
    BOOST_ASSERT(assignment.constant(0, 2) == 1445);
    BOOST_ASSERT(assignment.constant(0, 3) == 1446);
    BOOST_ASSERT(assignment.constant(0, 4) == 2);
    BOOST_ASSERT(assignment.rows_amount() == 5);

    const std::vector<copy_constraint_type> expected_copy_constraints = {
        {var(0, 0, false, var::column_type::public_input), var(0, 0, false, var::column_type::witness)},
        {var(0, 1, false, var::column_type::public_input), var(0, 3, false, var::column_type::witness)},
        {var(1, 3, false, var::column_type::witness), var(8, 3, false, var::column_type::witness)},
        {var(1, 0, false, var::column_type::witness), var(3, 3, false, var::column_type::witness)},
        {var(4, 3, false, var::column_type::witness), var(0, 2, false, var::column_type::public_input)},
        {var(0, 1, false, var::column_type::constant), var(6, 3, false, var::column_type::witness)},
        {var(7, 3, false, var::column_type::witness), var(0, 4, false, var::column_type::constant)}
    };

    BOOST_ASSERT(compare_copy_constraint_vectors<field_type>(circuit.copy_constraints(), expected_copy_constraints));

    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
}

BOOST_AUTO_TEST_CASE(component_batch_params_test) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = typename curve_type::scalar_field_type;

    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using circuit_type = circuit<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;
    using constraint_type = crypto3::zk::snark::plonk_constraint<field_type>;
    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<field_type>;

    using swap_component_type = components::flexible_swap<ArithmetizationType, field_type>;
    using input_type = typename swap_component_type::input_type;

    assignment_type assignment(15, 1, 1, 3);
    circuit_type circuit;
    public_input_var_maker<field_type> public_input_var_maker(assignment);
    constexpr std::size_t size_small = 1;
    constexpr std::size_t size_big = 2;
    input_type input;

    input.inp = {public_input_var_maker.binary_var(), public_input_var_maker(), public_input_var_maker()};
    auto res_1 =  assignment.add_input_to_batch_assignment<swap_component_type>(input);

    input.inp = {public_input_var_maker.binary_var(), public_input_var_maker(), public_input_var_maker()};
    auto res_2 = assignment.add_input_to_batch_assignment<swap_component_type>(input);

    input.inp = {public_input_var_maker.binary_var(), res_1.output[0], res_2.output[1]};
    auto res_3 = assignment.add_input_to_batch_assignment<swap_component_type>(input);
    assignment.finalize_component_batches(circuit, 0);

    BOOST_CHECK_EQUAL(circuit.gates().size(), 1);
    const auto &gate_1 = circuit.gates()[0];
    BOOST_CHECK_EQUAL(gate_1.constraints.size(), 9);
    std::array<constraint_type, 9> expected_constraints = {
        var(0, 0) * (var(0, 0) - 1),
        var(3, 0) - (((0 - (var(0, 0) - 1)) * var(1, 0)) + var(0, 0) * var(2, 0)),
        var(4, 0) - (((0 - (var(0, 0) - 1)) * var(2, 0)) + var(0, 0) * var(1, 0)),
        var(5, 0) * (var(5, 0) - 1),
        var(8, 0) - (((0 - (var(5, 0) - 1)) * var(6, 0)) + var(5, 0) * var(7, 0)),
        var(9, 0) - (((0 - (var(5, 0) - 1)) * var(7, 0)) + var(5, 0) * var(6, 0)),
        var(10, 0) * (var(10, 0) - 1),
        var(13, 0) - (((0 - (var(10, 0) - 1)) * var(11, 0)) + var(10, 0) * var(12, 0)),
        var(14, 0) - (((0 - (var(10, 0) - 1)) * var(12, 0)) + var(10, 0) * var(11, 0))
    };

    for (std::size_t i = 0; i < gate_1.constraints.size(); ++i) {
        BOOST_CHECK_EQUAL(gate_1.constraints[i], expected_constraints[i]);
    }

    const std::vector<copy_constraint_type> expected_copy_constraints = {
        {var(0, 0, false, var::column_type::public_input), var(0, 0, false, var::column_type::witness)},
        {var(0, 1, false, var::column_type::public_input), var(1, 0, false, var::column_type::witness)},
        {var(0, 2, false, var::column_type::public_input), var(2, 0, false, var::column_type::witness)},

        {var(0, 3, false, var::column_type::public_input), var(5, 0, false, var::column_type::witness)},
        {var(0, 4, false, var::column_type::public_input), var(6, 0, false, var::column_type::witness)},
        {var(0, 5, false, var::column_type::public_input), var(7, 0, false, var::column_type::witness)},

        {var(0, 6, false, var::column_type::public_input), var(10, 0, false, var::column_type::witness)},
        {var(3, 0, false, var::column_type::witness), var(11, 0, false, var::column_type::witness)},
        {var(9, 0, false, var::column_type::witness), var(12, 0, false, var::column_type::witness)}
    };

    BOOST_ASSERT(compare_copy_constraint_vectors<field_type>(circuit.copy_constraints(), expected_copy_constraints));

    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
}

BOOST_AUTO_TEST_CASE(component_batch_generate_circuit_variant_basic_test) {
    using curve_type = nil::crypto3::algebra::curves::vesta;
    using field_type = typename curve_type::scalar_field_type;

    using assignment_type = assignment<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using circuit_type = circuit<nil::crypto3::zk::snark::plonk_constraint_system<field_type>>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;

    assignment_type assignment(15, 1, 1, 3);
    circuit_type circuit;
    public_input_var_maker<field_type> public_input_var_maker(assignment);

    using multiplication_type = components::multiplication<
        ArithmetizationType, field_type, nil::blueprint::basic_non_native_policy<field_type>>;

    typename multiplication_type::input_type input_1 = {public_input_var_maker(), public_input_var_maker()};
    typename multiplication_type::input_type input_2 = {public_input_var_maker(), public_input_var_maker()};
    auto res_1 = assignment.add_input_to_batch_circuit<multiplication_type>(input_1);
    auto res_2 = assignment.add_input_to_batch_circuit<multiplication_type>(input_2);
    BOOST_ASSERT(var_value(assignment, res_1.output) == 0);
    BOOST_ASSERT(var_value(assignment, res_2.output) == 0);
    res_1 = assignment.add_input_to_batch_assignment<multiplication_type>(input_1);
    BOOST_ASSERT(var_value(assignment, res_1.output) == var_value(assignment, input_1.x) * var_value(assignment, input_1.y));
    BOOST_ASSERT(var_value(assignment, res_1.output) != 0);
    BOOST_ASSERT(var_value(assignment, res_2.output) == 0);
    res_2 = assignment.add_input_to_batch_assignment<multiplication_type>(input_2);
    BOOST_ASSERT(var_value(assignment, res_2.output) == var_value(assignment, input_2.x) * var_value(assignment, input_2.y));
    BOOST_ASSERT(var_value(assignment, res_2.output) != 0);
}

BOOST_AUTO_TEST_SUITE_END()

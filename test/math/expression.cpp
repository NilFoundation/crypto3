//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#define BOOST_TEST_MODULE expression_test

#include <string>
#include <random>
#include <iostream>
#include <set>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

BOOST_AUTO_TEST_SUITE(expression_tests_suite)

BOOST_AUTO_TEST_CASE(expression_to_non_linear_combination_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    variable_type w0(0, 0, variable_type::column_type::witness);
    variable_type w1(3, -1, variable_type::column_type::public_input);
    variable_type w2(4, 1, variable_type::column_type::public_input);
    variable_type w3(6, 2, variable_type::column_type::constant);

    expression<variable_type> expr = (w0 + w1) * (w2 + w3) - w1 * (w2 + w0);
   
    expression_to_non_linear_combination_visitor<variable_type> visitor;
    non_linear_combination<variable_type> result = visitor.convert(expr);
    non_linear_combination<variable_type> expected({w0 * w2, w0 * w3, w1 * w3, -w1 * w0});
 
    // We may get the terms in a different order due to changes in the code, and that's fine.
    BOOST_CHECK_EQUAL(result, expected);
}

BOOST_AUTO_TEST_CASE(expression_evaluation_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    variable_type w0(0, 0, variable_type::column_type::witness);
    variable_type w1(3, -1, variable_type::column_type::public_input);
    variable_type w2(4, 1, variable_type::column_type::public_input);
    variable_type w3(6, 2, variable_type::column_type::constant);

    expression<variable_type> expr = (w0 + w1) * (w2 + w3);
   
    expression_evaluator<variable_type> evaluator(
        expr,
        [&w0, &w1, &w2, &w3](const variable_type& var) {
            if (var == w0) return variable_type::assignment_type(1);
            if (var == w1) return variable_type::assignment_type(2);
            if (var == w2) return variable_type::assignment_type(3);
            if (var == w3) return variable_type::assignment_type(4);
            return variable_type::assignment_type::zero();
        }
    );
 
    BOOST_CHECK(evaluator.evaluate() == variable_type::assignment_type((1 + 2) * (3 + 4)));
}

BOOST_AUTO_TEST_CASE(expression_max_degree_visitor_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    variable_type w0(0, 0, variable_type::column_type::witness);
    variable_type w1(3, -1, variable_type::column_type::public_input);
    variable_type w2(4, 1, variable_type::column_type::public_input);
    variable_type w3(6, 2, variable_type::column_type::constant);

    expression<variable_type> expr = (w0 + w1) * (w2 + w3) + w0 * w1 * (w2 + w3);
   
    expression_max_degree_visitor<variable_type> visitor;

    BOOST_CHECK_EQUAL(visitor.compute_max_degree(expr), 3);
}

BOOST_AUTO_TEST_CASE(expression_for_each_variable_visitor_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    variable_type w0(0, 0, variable_type::column_type::witness);
    variable_type w1(3, -1, variable_type::column_type::public_input);
    variable_type w2(4, 1, variable_type::column_type::public_input);
    variable_type w3(6, 2, variable_type::column_type::constant);

    expression<variable_type> expr = (w0 + w1) * (w2 + w3) + w0 * w1 * (w2 + w3);
   
    std::set<int> variable_indices;
    std::set<int> variable_rotations;

    expression_for_each_variable_visitor<variable_type> visitor(
        [&variable_indices, &variable_rotations](const variable_type& var) {
            variable_indices.insert(var.index);
            variable_rotations.insert(var.rotation);
        }
    );

    visitor.visit(expr);

    std::set<int> expected_indices = {0, 3, 4, 6};
    std::set<int> expected_rotations = {0, -1, 1, 2};

    BOOST_CHECK_EQUAL_COLLECTIONS(
        variable_indices.begin(), variable_indices.end(),
        expected_indices.begin(), expected_indices.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        variable_rotations.begin(), variable_rotations.end(),
        expected_rotations.begin(), expected_rotations.end());
}

BOOST_AUTO_TEST_SUITE_END()

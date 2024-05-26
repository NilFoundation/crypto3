//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_constraint_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(plonk_constraint_test_suite)
    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    using var = zk::snark::plonk_variable<typename FieldType::value_type>;

    using constraint_type = zk::snark::plonk_constraint<FieldType>;
    using copy_constraint_type = zk::snark::plonk_copy_constraint<FieldType>;

BOOST_AUTO_TEST_CASE(plonk_constraint_basic_test) {
    constraint_type constraint = var(0, 0) + var(1, 0) - var(2, 0);
    constraint_type constraint1 = var(0, 0) + var(1, 0) - 2u;
    constraint_type constraint2 = 2u - (var(0, 0) + var(1, 0));
    constraint_type constraint3 = 2u - var(0, 0);
    constraint_type constraint4 = 2u - var(0, 0) * var(0, 0);
    constraint_type constraint5 = var(0, 0) - var(0, 0) * var(0, 0);
    constraint_type constraint6 = var(0, 0) * var(0, 0) + var(0, 0);
    constraint_type constraint7 = var(0, 0) * var(0, 0) - var(0, 0);
    constraint_type constraint8 = var(0, 0).pow(2u) - var(0, 0);
    constraint_type constraint9 = var(0, 0).pow(1u) - var(0, 0);

    std::vector<zk::snark::plonk_column<FieldType>> witness_columns(5);
    witness_columns[0] = {algebra::random_element<FieldType>()};
    witness_columns[1] = {algebra::random_element<FieldType>()};
    witness_columns[2] = {algebra::random_element<FieldType>()};

    std::cout << witness_columns[0][0].data << std::endl;
    std::cout << witness_columns[1][0].data << std::endl;
    std::cout << witness_columns[2][0].data << std::endl;

    zk::snark::plonk_private_assignment_table<FieldType> private_assignment(witness_columns);

    zk::snark::plonk_assignment_table<FieldType> assignment(private_assignment);

    BOOST_CHECK((witness_columns[0][0] + witness_columns[1][0] - witness_columns[2][0]) ==
                constraint.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] + witness_columns[1][0] - typename FieldType::value_type(2u)) ==
                constraint1.evaluate(0, assignment));

    BOOST_CHECK((typename FieldType::value_type(2u) - (witness_columns[0][0] + witness_columns[1][0])) ==
                constraint2.evaluate(0, assignment));

    BOOST_CHECK((typename FieldType::value_type(2u) - witness_columns[0][0]) == constraint3.evaluate(0, assignment));

    BOOST_CHECK((typename FieldType::value_type(2u) - witness_columns[0][0] * witness_columns[0][0]) ==
                constraint4.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] - witness_columns[0][0] * witness_columns[0][0]) ==
                constraint5.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] * witness_columns[0][0] + witness_columns[0][0]) ==
                constraint6.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] * witness_columns[0][0] - witness_columns[0][0]) ==
                constraint7.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0].pow(2u) - witness_columns[0][0]) == constraint8.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] - witness_columns[0][0]) == constraint9.evaluate(0, assignment));
}

BOOST_AUTO_TEST_CASE(plonk_copy_constraint_constructor_test) {
    var w0(0, 0, false, var::column_type::witness);
    var w0_1(0, 1, false, var::column_type::witness);
    var w1(1, 0, false, var::column_type::witness);
    var w1_1(1, 0, false, var::column_type::witness);
    var p0(0,0, false, var::column_type::public_input);
    var c0(0,0, false, var::column_type::constant);
    var s0(0,0, false, var::column_type::selector);
    var w(0, 0, true);

//    copy_constraint_type copy_constraint(w0, w0); // Fails with assersion
    copy_constraint_type cp0({w0, w0_1});  BOOST_ASSERT(cp0.first == w0 && cp0.second == w0_1);
    copy_constraint_type cp1({w0_1, w0}); BOOST_ASSERT(cp1.first == w0 && cp1.second == w0_1);
    copy_constraint_type cp2({w0, w1});   BOOST_ASSERT(cp2.first == w0 && cp2.second == w1);
    copy_constraint_type cp3({w1, w0});   BOOST_ASSERT(cp3.first == w0 && cp3.second == w1);
    copy_constraint_type cp4({w0_1, w1});   BOOST_ASSERT(cp4.first == w0_1 && cp4.second == w1);
    copy_constraint_type cp5({w1, w0_1});   BOOST_ASSERT(cp5.first == w0_1 && cp5.second == w1);
    copy_constraint_type cp6({w0, p0});   BOOST_ASSERT(cp6.first == w0 && cp6.second == p0);
    copy_constraint_type cp7({p0, w0});   BOOST_ASSERT(cp7.first == w0 && cp7.second == p0);
    copy_constraint_type cp8({w0, c0});   BOOST_ASSERT(cp8.first == w0 && cp8.second == c0);
    copy_constraint_type cp9({c0, w0});   BOOST_ASSERT(cp9.first == w0 && cp9.second == c0);
    copy_constraint_type cp10({w0, s0});   BOOST_ASSERT(cp10.first == w0 && cp10.second == s0);
    copy_constraint_type cp11({s0, w0});   BOOST_ASSERT(cp11.first == w0 && cp11.second == s0);
    copy_constraint_type cp12({p0, c0});   BOOST_ASSERT(cp12.first == p0 && cp12.second == c0);
    copy_constraint_type cp13({c0, p0});   BOOST_ASSERT(cp13.first == p0 && cp13.second == c0);
    copy_constraint_type cp14({p0, s0});   BOOST_ASSERT(cp14.first == p0 && cp14.second == s0);
    copy_constraint_type cp15({s0, p0});   BOOST_ASSERT(cp15.first == p0 && cp15.second == s0);
    copy_constraint_type cp16({c0, s0});   BOOST_ASSERT(cp16.first == c0 && cp16.second == s0);
    copy_constraint_type cp17({s0, c0});   BOOST_ASSERT(cp17.first == c0 && cp17.second == s0);
//    copy_constraint_type cp18({w0, w}); // Fails with assertion
}

BOOST_AUTO_TEST_SUITE_END()

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
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(plonk_constraint_test_suite)

BOOST_AUTO_TEST_CASE(plonk_constraint_basic_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    using var = zk::snark::plonk_variable<typename FieldType::value_type>;

    using constraint_type = zk::snark::plonk_constraint<FieldType>;

    constraint_type constraint = var(0, 0) + var(1, 0) - var(2, 0);
    constraint_type constraint1 = var(0, 0) + var(1, 0) - 2;
    constraint_type constraint2 = 2 - (var(0, 0) + var(1, 0));
    constraint_type constraint3 = 2 - var(0, 0);
    constraint_type constraint4 = 2 - var(0, 0) * var(0, 0);
    constraint_type constraint5 = var(0, 0) - var(0, 0) * var(0, 0);
    constraint_type constraint6 = var(0, 0) * var(0, 0) + var(0, 0);
    constraint_type constraint7 = var(0, 0) * var(0, 0) - var(0, 0);
    constraint_type constraint8 = var(0, 0).pow(2) - var(0, 0);
    constraint_type constraint9 = var(0, 0).pow(1) - var(0, 0);

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

    BOOST_CHECK((witness_columns[0][0] + witness_columns[1][0] - typename FieldType::value_type(2)) ==
                constraint1.evaluate(0, assignment));

    BOOST_CHECK((typename FieldType::value_type(2) - (witness_columns[0][0] + witness_columns[1][0])) ==
                constraint2.evaluate(0, assignment));

    BOOST_CHECK((typename FieldType::value_type(2) - witness_columns[0][0]) == constraint3.evaluate(0, assignment));

    BOOST_CHECK((typename FieldType::value_type(2) - witness_columns[0][0] * witness_columns[0][0]) ==
                constraint4.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] - witness_columns[0][0] * witness_columns[0][0]) ==
                constraint5.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] * witness_columns[0][0] + witness_columns[0][0]) ==
                constraint6.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] * witness_columns[0][0] - witness_columns[0][0]) ==
                constraint7.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0].pow(2) - witness_columns[0][0]) == constraint8.evaluate(0, assignment));

    BOOST_CHECK((witness_columns[0][0] - witness_columns[0][0]) == constraint9.evaluate(0, assignment));
}

BOOST_AUTO_TEST_SUITE_END()

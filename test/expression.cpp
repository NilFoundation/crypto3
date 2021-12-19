//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE expression_arithmetic_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/math/expression.hpp>
#include <nil/crypto3/math/polynomial/polynom.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

typedef fields::bls12<381> FieldType;

BOOST_AUTO_TEST_SUITE(expression_test_suite)

BOOST_AUTO_TEST_CASE(expression_field_evaluation) {

    constexpr static typename expression::variable_type<0> const _0;
    constexpr static typename expression::variable_type<1> const _1;

    auto expr = (_1 - _0) + _1 * 100;

    typename expression::assignment_type<typename FieldType::value_type, 2> ctx;

    ctx[0] = typename FieldType::value_type(100);
    ctx[1] = typename FieldType::value_type(505);

    typename FieldType::value_type d = expression::eval( expr, ctx );

    BOOST_CHECK_EQUAL((505 - 100) + 505*100, d.data);
}

BOOST_AUTO_TEST_CASE(expression_polynom_evaluation) {

    constexpr static typename expression::variable_type<0> const _0;
    constexpr static typename expression::variable_type<1> const _1;

    auto expr = _1 + _0;

    typename expression::assignment_type<polynomial::polynom<typename FieldType::value_type>, 2> ctx;

    ctx[0] = {1, 3, 4, 25, 6, 7, 7, 2};
    ctx[1] = {9, 3, 11, 14, 7, 1, 5, 8};

    polynomial::polynom<typename FieldType::value_type> c_ans = {10, 6, 15, 39, 13, 8, 12, 10};

    polynomial::polynom<typename FieldType::value_type> d = expression::eval( expr, ctx );

    for (std::size_t i = 0; i < d.size(); ++i) {
        BOOST_CHECK_EQUAL(c_ans[i].data, d[i].data);
    }
}

BOOST_AUTO_TEST_CASE(expression_polynom_and_field_evaluation) {

    constexpr static typename expression::variable_type<0> const _0;
    constexpr static typename expression::variable_type<1> const _1;

    auto expr = _1 + _0;

    typename expression::assignment_type<polynomial::polynom<typename FieldType::value_type>, 2> polynom_ctx;

    polynom_ctx[0] = {1, 3, 4, 25, 6, 7, 7, 2};
    polynom_ctx[1] = {9, 3, 11, 14, 7, 1, 5, 8};

    polynomial::polynom<typename FieldType::value_type> c_ans = {10, 6, 15, 39, 13, 8, 12, 10};

    polynomial::polynom<typename FieldType::value_type> d = expression::eval( expr, polynom_ctx );

    for (std::size_t i = 0; i < d.size(); ++i) {
        BOOST_CHECK_EQUAL(c_ans[i].data, d[i].data);
    }

    typename expression::assignment_type<typename FieldType::value_type, 2> field_ctx;

    field_ctx[0] = typename FieldType::value_type(100);
    field_ctx[1] = typename FieldType::value_type(505);

    typename FieldType::value_type e = expression::eval( expr, field_ctx );

    BOOST_CHECK_EQUAL(505 + 100, e.data);
}

BOOST_AUTO_TEST_SUITE_END()
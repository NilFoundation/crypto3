//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#define BOOST_TEST_MODULE polynomial_view_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/math/polynomial/polynomial_view.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

typedef fields::bls12_fr<381> FieldType;

BOOST_AUTO_TEST_SUITE(polynomial_constructor_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_constructor) {

    std::vector<typename FieldType::value_type> a_v = {0, 0, 0, 0, 0, 1};
    polynomial_view<typename FieldType::value_type> a(a_v);

    for (std::size_t i = 0; i < a_v.size(); i++) {
        BOOST_CHECK_EQUAL(a[i].data, a_v[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_addition_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_addition_equal) {
    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b_v = {9, 3, 11, 14, 7, 1, 5, 8};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a += b;

    std::vector<typename FieldType::value_type> a_ans = {10, 6, 15, 39, 13, 8, 12, 10};

    for (std::size_t i = 0; i < a_ans.size(); ++i) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_long_a) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b_v = {9, 3, 11, 14, 7};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a += b;

    std::vector<typename FieldType::value_type> a_ans = {10, 6, 15, 39, 13, 7, 7, 2};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_long_b) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6};
    std::vector<typename FieldType::value_type> b_v = {9, 3, 11, 14, 7, 1, 5, 8};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a += b;

    std::vector<typename FieldType::value_type> a_ans = {10, 6, 15, 39, 13, 1, 5, 8};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_zero_a) {

    std::vector<typename FieldType::value_type> a_v = {0, 0, 0};
    std::vector<typename FieldType::value_type> b_v = {1, 3, 4, 25, 6, 7, 7, 2};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a += b;

    std::vector<typename FieldType::value_type> a_ans = {1, 3, 4, 25, 6, 7, 7, 2};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_zero_b) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b_v = {0, 0, 0};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a += b;

    std::vector<typename FieldType::value_type> a_ans = {1, 3, 4, 25, 6, 7, 7, 2};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_subtraction_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_subtraction_equal) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b_v = {9, 3, 11, 14, 7, 1, 5, 8};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a -= b;

    std::vector<typename FieldType::value_type> a_ans = {-8, 0, -7, 11, -1, 6, 2, -6};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_long_a) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b_v = {9, 3, 11, 14, 7};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a -= b;

    std::vector<typename FieldType::value_type> a_ans = {-8, 0, -7, 11, -1, 7, 7, 2};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_long_b) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6};
    std::vector<typename FieldType::value_type> b_v = {9, 3, 11, 14, 7, 1, 5, 8};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a -= b;

    std::vector<typename FieldType::value_type> a_ans = {-8, 0, -7, 11, -1, -1, -5, -8};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_zero_a) {

    std::vector<typename FieldType::value_type> a_v = {0, 0, 0};
    std::vector<typename FieldType::value_type> b_v = {1, 3, 4, 25, 6, 7, 7, 2};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a -= b;

    std::vector<typename FieldType::value_type> a_ans = {-1, -3, -4, -25, -6, -7, -7, -2};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_zero_b) {

    std::vector<typename FieldType::value_type> a_v = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b_v = {0, 0, 0};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a -= b;

    std::vector<typename FieldType::value_type> a_ans = {1, 3, 4, 25, 6, 7, 7, 2};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_multiplication_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_multiplication_long_a) {

    std::vector<typename FieldType::value_type> a_v = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b_v = {13, 0, 1};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a *= b;

    std::vector<typename FieldType::value_type> a_ans = {65, 0, 5, 169, 0, 26, 0, 1};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_multiplication_long_b) {

    std::vector<typename FieldType::value_type> a_v = {13, 0, 1};
    std::vector<typename FieldType::value_type> b_v = {5, 0, 0, 13, 0, 1};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a *= b;

    std::vector<typename FieldType::value_type> a_ans = {65, 0, 5, 169, 0, 26, 0, 1};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_multiplication_zero_a) {

    std::vector<typename FieldType::value_type> a_v = {0};
    std::vector<typename FieldType::value_type> b_v = {5, 0, 0, 13, 0, 1};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a *= b;

    std::vector<typename FieldType::value_type> a_ans = {0};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_multiplication_zero_b) {

    std::vector<typename FieldType::value_type> a_v = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b_v = {0};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    a *= b;

    std::vector<typename FieldType::value_type> a_ans = {0};

    for (std::size_t i = 0; i < a_ans.size(); i++) {
        BOOST_CHECK_EQUAL(a_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_division_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_div) {

    std::vector<typename FieldType::value_type> a_v = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b_v = {13, 0, 1};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    std::vector<typename FieldType::value_type> q_ans = {0, 0, 0, 1};

    a /= b;

    for (std::size_t i = 0; i < q_ans.size(); ++i) {
        BOOST_CHECK_EQUAL(q_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_mod) {

    std::vector<typename FieldType::value_type> a_v = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b_v = {13, 0, 1};

    polynomial_view<typename FieldType::value_type> a(a_v);
    polynomial_view<typename FieldType::value_type> b(b_v);

    std::vector<typename FieldType::value_type> r_ans = {5};

    a %= b;

    for (std::size_t i = 0; i < r_ans.size(); ++i) {
        BOOST_CHECK_EQUAL(r_ans[i].data, a[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()
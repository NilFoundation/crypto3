//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE polynomial_arithmetic_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/fft/polynomial_arithmetic/basic_operations.hpp>
#include <nil/crypto3/fft/polynomial_arithmetic/xgcd.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::fft;

typedef fields::bls12<381> FieldType;

BOOST_AUTO_TEST_SUITE(polynomial_addition_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_addition_equal) {
    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b = {9, 3, 11, 14, 7, 1, 5, 8};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_addition<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {10, 6, 15, 39, 13, 8, 12, 10};

    for (std::size_t i = 0; i < c.size(); ++i) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_long_a) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b = {9, 3, 11, 14, 7};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_addition<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {10, 6, 15, 39, 13, 7, 7, 2};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_long_b) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6};
    std::vector<typename FieldType::value_type> b = {9, 3, 11, 14, 7, 1, 5, 8};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_addition<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {10, 6, 15, 39, 13, 1, 5, 8};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_zero_a) {

    std::vector<typename FieldType::value_type> a = {0, 0, 0};
    std::vector<typename FieldType::value_type> b = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_addition<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {1, 3, 4, 25, 6, 7, 7, 2};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_addition_zero_b) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b = {0, 0, 0};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_addition<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {1, 3, 4, 25, 6, 7, 7, 2};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_subtraction_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_subtraction_equal) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b = {9, 3, 11, 14, 7, 1, 5, 8};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_subtraction<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {-8, 0, -7, 11, -1, 6, 2, -6};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_long_a) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b = {9, 3, 11, 14, 7};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_subtraction<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {-8, 0, -7, 11, -1, 7, 7, 2};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_long_b) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6};
    std::vector<typename FieldType::value_type> b = {9, 3, 11, 14, 7, 1, 5, 8};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_subtraction<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {-8, 0, -7, 11, -1, -1, -5, -8};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_zero_a) {

    std::vector<typename FieldType::value_type> a = {0, 0, 0};
    std::vector<typename FieldType::value_type> b = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_subtraction<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {-1, -3, -4, -25, -6, -7, -7, -2};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_subtraction_zero_b) {

    std::vector<typename FieldType::value_type> a = {1, 3, 4, 25, 6, 7, 7, 2};
    std::vector<typename FieldType::value_type> b = {0, 0, 0};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_subtraction<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {1, 3, 4, 25, 6, 7, 7, 2};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_multiplication_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_multiplication_long_a) {

    std::vector<typename FieldType::value_type> a = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b = {13, 0, 1};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_multiplication<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {65, 0, 5, 169, 0, 26, 0, 1};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_multiplication_long_b) {

    std::vector<typename FieldType::value_type> a = {13, 0, 1};
    std::vector<typename FieldType::value_type> b = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_multiplication<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {65, 0, 5, 169, 0, 26, 0, 1};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_multiplication_zero_a) {

    std::vector<typename FieldType::value_type> a = {0};
    std::vector<typename FieldType::value_type> b = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_multiplication<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {0};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_multiplication_zero_b) {

    std::vector<typename FieldType::value_type> a = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b = {0};
    std::vector<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    _polynomial_multiplication<FieldType>(c, a, b);

    std::vector<typename FieldType::value_type> c_ans = {0};

    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(polynomial_division) {

    std::vector<typename FieldType::value_type> a = {5, 0, 0, 13, 0, 1};
    std::vector<typename FieldType::value_type> b = {13, 0, 1};

    std::vector<typename FieldType::value_type> Q(1, FieldType::value_type::zero());
    std::vector<typename FieldType::value_type> R(1, FieldType::value_type::zero());

    _polynomial_division<FieldType>(Q, R, a, b);

    std::vector<typename FieldType::value_type> Q_ans = {0, 0, 0, 1};
    std::vector<typename FieldType::value_type> R_ans = {5};

    for (std::size_t i = 0; i < Q.size(); i++) {
        BOOST_CHECK_EQUAL(Q_ans[i].data, Q[i].data);
    }
    for (std::size_t i = 0; i < R.size(); i++) {
        BOOST_CHECK_EQUAL(R_ans[i].data, R[i].data);
    }
}

BOOST_AUTO_TEST_CASE(extended_gcd) {

    std::vector<typename FieldType::value_type> a = {0, 0, 0, 0, 1};
    std::vector<typename FieldType::value_type> b = {1, -6, 11, -6};

    std::vector<typename FieldType::value_type> pg(1, FieldType::value_type::zero());
    std::vector<typename FieldType::value_type> pu(1, FieldType::value_type::zero());
    std::vector<typename FieldType::value_type> pv(1, FieldType::value_type::zero());

    _polynomial_xgcd<FieldType>(a, b, pg, pu, pv);

    std::vector<typename FieldType::value_type> pv_ans = {1, 6, 25, 90};

    for (std::size_t i = 0; i < pv.size(); i++) {
        BOOST_CHECK_EQUAL(pv_ans[i].data, pv[i].data);
    }
}

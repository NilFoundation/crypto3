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

#define BOOST_TEST_MODULE polynomial_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

typedef fields::bls12_fr<381> FieldType;

BOOST_AUTO_TEST_SUITE(field_utils_test_suite)

    BOOST_DATA_TEST_CASE(is_power_of_two,
                         boost::unit_test::data::make({1u, 2u, 4u, 8u, 16u, 32u, 512u, 1024u, 2048u, 4096u, 16384u, 32768u}),
                         iterator) {
        BOOST_CHECK(nil::crypto3::math::detail::is_power_of_two(iterator));
    }

    BOOST_DATA_TEST_CASE(is_not_power_of_two,
                         boost::unit_test::data::make({0u, 3u, 5u, 7u, 9u, 31u, 33u, 1025u, 4095u}),
                         iterator) {
        BOOST_CHECK(!nil::crypto3::math::detail::is_power_of_two(iterator));
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_constructor_test_suite)

    BOOST_AUTO_TEST_CASE(polynomial_constructor) {

        polynomial<typename FieldType::value_type> a(FieldType::value_type::one(), 5);
        polynomial<typename FieldType::value_type> a_expected = {0u, 0u, 0u, 0u, 0u, 1u};

        BOOST_CHECK_EQUAL(a_expected, a);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_addition_test_suite)

    void test_addition(polynomial<typename FieldType::value_type> a,
                       polynomial<typename FieldType::value_type> b,
                       polynomial<typename FieldType::value_type> c_ans) {
        auto c = a + b;
        BOOST_CHECK_EQUAL(c_ans, c);

        a += b;
        BOOST_CHECK_EQUAL(c_ans, a);
    }

    BOOST_AUTO_TEST_CASE(polynomial_addition_equal) {
        test_addition({1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {9u, 3u, 11u, 14u, 7u, 1u, 5u, 8u}, {10u, 6u, 15u, 39u, 13u, 8u, 12u, 10u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_addition_long_a) {
        test_addition({1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {9u, 3u, 11u, 14u, 7u}, {10u, 6u, 15u, 39u, 13u, 7u, 7u, 2u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_addition_long_b) {
        test_addition({1u, 3u, 4u, 25u, 6u}, {9u, 3u, 11u, 14u, 7u, 1u, 5u, 8u}, {10u, 6u, 15u, 39u, 13u, 1u, 5u, 8u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_addition_zero_a) {
        test_addition({0u, 0u, 0u}, {1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_addition_zero_b) {
        test_addition({1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {0u, 0u, 0u}, {1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u});
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_subtraction_test_suite)

    void test_substraction(polynomial<typename FieldType::value_type> a,
                           polynomial<typename FieldType::value_type> b,
                           polynomial<typename FieldType::value_type> c_ans) {
        auto c = a - b;
        BOOST_CHECK_EQUAL(c_ans, c);

        a -= b;
        BOOST_CHECK_EQUAL(c_ans, a);
    }

    BOOST_AUTO_TEST_CASE(polynomial_subtraction_equal) {
        test_substraction({1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {9u, 3u, 11u, 14u, 7u, 1u, 5u, 8u}, 
            {FieldType::modulus - 8u, 0u, FieldType::modulus - 7u, 11u, FieldType::modulus - 1u, 6u, 2u, FieldType::modulus - 6u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_subtraction_long_a) {
        test_substraction({1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {9u, 3u, 11u, 14u, 7u},
            {FieldType::modulus - 8u, 0u, FieldType::modulus - 7u, 11u, FieldType::modulus - 1u, 7u, 7u, 2u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_subtraction_long_b) {
        test_substraction({1u, 3u, 4u, 25u, 6u}, {9u, 3u, 11u, 14u, 7u, 1u, 5u, 8u}, 
            {FieldType::modulus - 8u, 0u, FieldType::modulus - 7u, 11u, FieldType::modulus - 1u, FieldType::modulus - 1u,
             FieldType::modulus - 5u, FieldType::modulus - 8u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_subtraction_zero_a) {
        test_substraction({0u, 0u, 0u}, {1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, 
            {FieldType::modulus - 1, FieldType::modulus - 3, FieldType::modulus - 4, FieldType::modulus - 25, 
             FieldType::modulus - 6, FieldType::modulus - 7, FieldType::modulus - 7, FieldType::modulus - 2});
    }

    BOOST_AUTO_TEST_CASE(polynomial_subtraction_zero_b) {
        test_substraction({1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u}, {0u, 0u, 0u}, {1u, 3u, 4u, 25u, 6u, 7u, 7u, 2u});
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_multiplication_test_suite)

    void test_multiplication(polynomial<typename FieldType::value_type> a,
                             polynomial<typename FieldType::value_type> b,
                             polynomial<typename FieldType::value_type> c_ans) {
        auto c = a * b;
        BOOST_CHECK_EQUAL(c_ans, c);

        a *= b;
        BOOST_CHECK_EQUAL(c_ans, a);
    }

    BOOST_AUTO_TEST_CASE(polynomial_multiplication_long_a) {
        test_multiplication({5u, 0u, 0u, 13u, 0u, 1u}, {13u, 0u, 1u}, {65u, 0u, 5u, 169u, 0u, 26u, 0u, 1u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_multiplication_long_b) {
        test_multiplication({13u, 0u, 1u}, {5u, 0u, 0u, 13u, 0u, 1u}, {65u, 0u, 5u, 169u, 0u, 26u, 0u, 1u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_multiplication_zero_a) {
        test_multiplication({0u}, {5u, 0u, 0u, 13u, 0u, 1u}, {0u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_multiplication_zero_b) {
        test_multiplication({5u, 0u, 0u, 13u, 0u, 1u}, {0u}, {0u});
    }

/* this should throw an assertion
BOOST_AUTO_TEST_CASE(polynomial_multiplication_constant_a_empty_b){

    polynomial<typename FieldType::value_type> a = {1};
    polynomial<typename FieldType::value_type> b = {};
    polynomial<typename FieldType::value_type> c(1, FieldType::value_type::zero());

    c = a * b;
}*/

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_division_test_suite)

    void test_division(
            polynomial<typename FieldType::value_type> a, polynomial<typename FieldType::value_type> b,
            polynomial<typename FieldType::value_type> Q_ans, polynomial<typename FieldType::value_type> R_ans) {
        auto Q = a / b;
        auto R = a % b;

        BOOST_CHECK_EQUAL(Q_ans, Q);
        BOOST_CHECK_EQUAL(R_ans, R);

        auto a1 = a;
        a1 /= b;
        BOOST_CHECK_EQUAL(Q_ans, a1);

        a1 = a;
        a1 %= b;
        BOOST_CHECK_EQUAL(R_ans, a1);
    }

    BOOST_AUTO_TEST_CASE(polynomial_division) {
        test_division({5u, 0u, 0u, 13u, 0u, 1u}, {13u, 2u, 1u}, {18u, 4u, FieldType::modulus - 2u, 1u}, 
            {FieldType::modulus - 229u, FieldType::modulus - 88u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_division_horner_binomial) {
        test_division({2u, 0u, 3u, 2u, 1u}, {FieldType::modulus - 2u, 1u}, {22u, 11u, 4u, 1u}, {46u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_division_horner_long_second) {
        test_division({2u, 0u, 3u, 2u, 1u}, {FieldType::modulus - 2u, 0u, 0u, 1u}, {2u, 1u}, {6u, 2u, 3u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_division_horner_long_equal) {
        test_division({2u, 0u, 3u, 2u, 2u}, {FieldType::modulus - 2u, 0u, 0u, 0u, 1u}, {2u}, {6u, 0u, 3u, 2u});
    }

    BOOST_AUTO_TEST_CASE(polynomial_division_on_zero_degree_polys) {
        test_division({0u, 1u}, {1u}, {0u, 1u}, {0u});
        test_division({0u, 4u}, {2u}, {0u, 2u}, {0u});
        test_division({2u, 0u, 3u, 2u, 2u}, {1u}, {2u, 0u, 3u, 2u, 2u}, {0u});
        test_division({4u, 0u, 4u, 2u, 2u}, {2u}, {2u, 0u, 2u, 1u, 1u}, {0u});
    }

BOOST_AUTO_TEST_SUITE_END()

//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE NON_MATCHING_BITLENGTH_NUMBERS_TESTS

// Suddenly, BOOST_MP_ASSERT is NOT constexpr, and it is used in constexpr functions throughout the boost, resulting to compilation errors on all compilers in debug mode. We need to switch assertions off inside cpp_int to make this code compile in debug mode. So we use this workaround to turn off file 'boost/multiprecision/detail/assert.hpp' which contains definition of BOOST_MP_ASSERT and BOOST_MP_ASSERT_MSG. 
#ifndef BOOST_MP_DETAIL_ASSERT_HPP
    #define BOOST_MP_DETAIL_ASSERT_HPP
    #define BOOST_MP_ASSERT(expr) ((void)0)
    #define BOOST_MP_ASSERT_MSG(expr, msg) ((void)0)
#endif

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <iostream>
#include <vector>

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

// We need cpp_int to compare to it.
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>
#include <nil/crypto3/multiprecision/inverse.hpp>

using namespace boost::multiprecision;

using boost::multiprecision::backends::cpp_int_modular_backend;

// This test case uses normal boost::cpp_int for comparison to our cpp_int_modular_backend.
template<unsigned Bits1, unsigned Bits2>
void value_comparisons_tests(const number<cpp_int_modular_backend<Bits1>>& a,
                          const number<cpp_int_modular_backend<Bits2>>& b) {

    typedef cpp_int_modular_backend<Bits1> Backend1;
    typedef cpp_int_modular_backend<Bits2> Backend2;
    typedef cpp_int_modular_backend<Bits1 + Bits2> Backend_large;
    typedef typename Backend1::cpp_int_type CppIntBackend1;
    typedef typename Backend2::cpp_int_type CppIntBackend2;
    typedef typename Backend_large::cpp_int_type CppIntBackend_large;

    typedef boost::multiprecision::number<CppIntBackend1> cpp_int_number1;
    typedef boost::multiprecision::number<CppIntBackend2> cpp_int_number2;
    typedef boost::multiprecision::number<CppIntBackend_large> cpp_int_number_large;

    // Convert from cpp_int_modular_backend to cpp_int_backend numbers.
    cpp_int_number1 a_cppint = a.backend().to_cpp_int();
    cpp_int_number2 b_cppint = b.backend().to_cpp_int();

    BOOST_ASSERT_MSG((a > b) == (a_cppint > b_cppint), "g error");
    BOOST_ASSERT_MSG((a >= b) == (a_cppint >= b_cppint), "ge error");
    BOOST_ASSERT_MSG((a == b) == (a_cppint == b_cppint), "e error");
    BOOST_ASSERT_MSG((a < b) == (a_cppint < b_cppint), "l error");
    BOOST_ASSERT_MSG((a <= b) == (a_cppint <= b_cppint), "le error");
    BOOST_ASSERT_MSG((a != b) == (a_cppint != b_cppint), "ne error");
}

template<unsigned Bits1, unsigned Bits2>
void value_comparisons_tests(const std::size_t N) {
    using Backend1 = cpp_int_modular_backend<130>;
    using Backend2 = cpp_int_modular_backend<260>;
    using standard_number1 = boost::multiprecision::number<Backend1>;
    using standard_number2 = boost::multiprecision::number<Backend2>;

    int seed = 0;
    boost::random::mt19937 gen(seed);
    boost::random::uniform_int_distribution<standard_number1> d1(0, ~standard_number1(0u));
    boost::random::uniform_int_distribution<standard_number2> d2(0, ~standard_number2(0u));

    for (std::size_t i = 0; i < N; ++i) {
        standard_number1 a = d1(gen);
        standard_number2 b = d2(gen);
        value_comparisons_tests(a, b);
    }
}


BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(base_test_backend_12_17) {
    value_comparisons_tests<12, 17>(1000);
}

BOOST_AUTO_TEST_CASE(base_test_backend_130_260) {
    value_comparisons_tests<260, 130>(1000);
}

BOOST_AUTO_TEST_CASE(base_test_backend_128_256) {
    value_comparisons_tests<128, 256>(1000);
}

BOOST_AUTO_TEST_SUITE_END()

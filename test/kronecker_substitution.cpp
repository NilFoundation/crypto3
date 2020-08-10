//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE kronecker_substitution_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/fft/polynomial_arithmetic/basic_operations.hpp>
#include <nil/algebra/fft/kronecker_substitution.hpp>

using namespace nil::algebra::fft;

typedef nil::algebra::Double FieldT;

BOOST_AUTO_TEST_SUITE(kronecker_substitution_test_suite)

BOOST_AUTO_TEST_CASE(standard_polynomial_multiplication) {

    std::vector<FieldT> a = {1, 2, 3, 1};
    std::vector<FieldT> b = {1, 2, 1, 1};
    std::vector<FieldT> c(1, FieldT::zero());

    _polynomial_multiplication_on_kronecker(c, a, b);

    std::vector<FieldT> c_answer(1, FieldT::zero());
    _polynomial_multiplication(c_answer, a, b);

    for (size_t i = 0; i < c_answer.size(); i++) {
        BOOST_CHECK(c_answer[i] == c[i]);
    }
}

BOOST_AUTO_TEST_CASE(squared_polynomial_multiplication) {

    std::vector<FieldT> a = {1, 2, 3, 1};
    std::vector<FieldT> b = a;
    std::vector<FieldT> c(1, FieldT::zero());

    _polynomial_multiplication_on_kronecker(c, a, b);

    std::vector<FieldT> c_answer(1, FieldT::zero());
    _polynomial_multiplication(c_answer, a, b);

    for (size_t i = 0; i < c_answer.size(); i++) {
        BOOST_CHECK(c_answer[i] == c[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
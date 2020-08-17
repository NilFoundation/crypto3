//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Test program that exercises the ppzkSNARK (first generator, then
// prover, then verifier) on a synthetic USCS instance.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE uscs_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstdio>

#include "uscs_examples.hpp"
#include "run_uscs_ppzksnark.hpp"

using namespace nil::crypto3::zk::snark;

template<typename ppT>
void test_uscs_ppzksnark(size_t num_constraints, size_t input_size) {
    const bool test_serialization = true;
    uscs_example<algebra::Fr<ppT>> example =
        generate_uscs_example_with_binary_input<algebra::Fr<ppT>>(num_constraints, input_size);
    const bool bit = run_uscs_ppzksnark<ppT>(example, test_serialization);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(uscs_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(uscs_ppzksnark_test) {
    test_uscs_ppzksnark<default_uscs_ppzksnark_pp>(1000, 100);
}

BOOST_AUTO_TEST_SUITE_END()

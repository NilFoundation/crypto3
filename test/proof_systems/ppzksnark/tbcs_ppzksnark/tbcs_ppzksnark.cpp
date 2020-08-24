//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Test program that exercises the ppzkSNARK (first generator, then
// prover, then verifier) on a synthetic TBCS instance.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE tbcs_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstdio>

#include "tbcs_examples.hpp"
#include "run_tbcs_ppzksnark.hpp"

using namespace nil::crypto3::zk::snark;

template<typename CurveType>
void test_tbcs_ppzksnark(std::size_t primary_input_size, std::size_t auxiliary_input_size, std::size_t num_gates, std::size_t num_outputs) {
    const tbcs_example example =
        generate_tbcs_example(primary_input_size, auxiliary_input_size, num_gates, num_outputs);

    const bool bit = run_tbcs_ppzksnark<CurveType>(example);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(tbcs_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(tbcs_ppzksnark_test) {
    test_tbcs_ppzksnark<default_tbcs_ppzksnark_pp>(10, 10, 20, 5);
}

BOOST_AUTO_TEST_SUITE_END()

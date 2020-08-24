//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE bacs_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <cstdio>

#include "bacs_examples.hpp"
#include "run_bacs_ppzksnark.hpp"

using namespace nil::crypto3::zk::snark;

template<typename CurveType>
void test_bacs_ppzksnark(std::size_t primary_input_size, std::size_t auxiliary_input_size, std::size_t num_gates, std::size_t num_outputs) {
    const bacs_example<typename CurveType::scalar_field_type> example =
        generate_bacs_example<typename CurveType::scalar_field_type>(primary_input_size, auxiliary_input_size, num_gates, num_outputs);
    const bool bit = run_bacs_ppzksnark<CurveType>(example);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(bacs_ppzksnark_test_suite)

BOOST_AUTO_TEST_CASE(bacs_ppzksnark_test) {
    test_bacs_ppzksnark<default_bacs_ppzksnark_pp>(10, 10, 20, 5);
}

BOOST_AUTO_TEST_SUITE_END()

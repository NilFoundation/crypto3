//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE r1cs_sp_ppzkpcd_test

#include <boost/test/unit_test.hpp>

#include "run_r1cs_sp_ppzkpcd.hpp"

using namespace nil::crypto3::zk::snark;

template<typename PCD_ppT>
void test_tally(const size_t arity, const size_t max_layer) {
    const size_t wordsize = 32;
    const bool test_serialization = true;
    const bool bit = run_r1cs_sp_ppzkpcd_tally_example<PCD_ppT>(wordsize, arity, max_layer, test_serialization);
    BOOST_CHECK(bit);
}

BOOST_AUTO_TEST_SUITE(r1cs_sp_ppzkpcd_test_suite)

BOOST_AUTO_TEST_CASE(r1cs_sp_ppzkpcd_test) {
    typedef default_r1cs_ppzkpcd_pp PCD_pp;

    const size_t arity = 2;
    const size_t max_layer = 2;

    test_tally<PCD_pp>(arity, max_layer);
}

BOOST_AUTO_TEST_SUITE_END()

//---------------------------------------------------------------------------//
//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sp800_108_test

#include <nil/crypto3/kdf/algorithm/derive.hpp>

#include <nil/crypto3/kdf/sp800_108.hpp>
#include <nil/crypto3/kdf/kdf_state.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <cstdio>
#include <cstring>

using namespace nil::crypto3::kdf;

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

BOOST_AUTO_TEST_SUITE(sp800_108_test_suite)

BOOST_AUTO_TEST_CASE(sp800_108_128_range_hash) {

}

BOOST_AUTO_TEST_SUITE_END()
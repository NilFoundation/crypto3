//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Nil Foundation AG
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE passhash9_test

#include <nil/crypto3/passhash/algorithm/generate.hpp>
#include <nil/crypto3/passhash/algorithm/check.hpp>

#include <nil/crypto3/passhash/passhash9.hpp>
#include <nil/crypto3/passhash/passhash_state.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <cstdio>
#include <cstring>

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

static const std::unordered_map<std::string, std::string> string_data
    = {{"", "cdf26213a150dc3ecb610f18f6b38b46"},
       {"a", "86be7afa339d0fc7cfc785e72f578d33"},
       {"abc", "c14a12199c66e4ba84636b0f69144c77"},
       {"message digest", "9e327b3d6e523062afc1132d7df9d1b8"},
       {"abcdefghijklmnopqrstuvwxyz", "fd2aa607f71dc8f510714922b371834e"},
       {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "a1aa0689d0fafa2ddc22e88b49133a06"},
       {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d1e959eb179c911faea4624c60c5c702"}};

BOOST_AUTO_TEST_SUITE(passhash9_test_suite)

BOOST_DATA_TEST_CASE(passhash9_range_hash, boost::unit_test::data::make(string_data), array_element) {
}

BOOST_AUTO_TEST_SUITE_END()
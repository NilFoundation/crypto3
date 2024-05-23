//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
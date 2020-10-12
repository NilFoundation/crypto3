//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Pavel Kharitonov <ipavrus@nil.foundation>
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

#define BOOST_TEST_MODULE tiger_test

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/tiger.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <cstdio>

using namespace nil::crypto3;
using namespace nil::crypto3::accumulators;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::tiger<192>::digest_type)

template<std::size_t Size>
class fixture {
public:
    accumulator_set<hashes::tiger<Size>> acc;
    typedef hashes::tiger<Size> hash_t;
    virtual ~fixture() {
    }
};

const char *test_data = "data/tiger.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(tiger_test_suite1)

BOOST_DATA_TEST_CASE(tiger_algorithm_test, string_data("data_192"), array_element) {
    std::string out = hash<hashes::tiger<192>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(tiger_adaptor_test, string_data("data_192"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::tiger<192>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(tiger_test_suite2)

BOOST_AUTO_TEST_CASE(tiger_iterator_hash1) {

    std::string input = "a";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809", out);
}

BOOST_AUTO_TEST_CASE(tiger_iterator_hash2) {

    std::string input = "abc";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", out);
}

BOOST_AUTO_TEST_CASE(tiger_iterator_hash3) {

    std::string input = "message digest";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6", out);
}

BOOST_AUTO_TEST_CASE(tiger_iterator_hash4) {

    std::string input = "abcdefghijklmnopqrstuvwxyz";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("1714a472eee57d30040412bfcc55032a0b11602ff37beee9", out);
}

BOOST_AUTO_TEST_CASE(tiger_iterator_hash5) {

    std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e", out);
}

BOOST_AUTO_TEST_CASE(tiger_iterator_hash6) {

    std::string input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc", out);
}

BOOST_AUTO_TEST_CASE(tiger_iterator_hash7) {

    std::string input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    std::string out = hash<hashes::tiger<192>>(input.begin(), input.end());

    BOOST_CHECK_EQUAL("1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd", out);
}

BOOST_AUTO_TEST_SUITE_END()
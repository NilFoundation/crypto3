//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE keccak_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <string>
#include <unordered_map>

using namespace nil::crypto3::hash;
using namespace nil::crypto3::accumulators;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream&, P<K, V> const&) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

static const std::unordered_map<std::string, std::string> string_data = {
    {"\x2", "00030003"},
    {"\x2\x4", "000a0007"},
    {"", "00000001"},
    {"a", "00620062"},
    {"abc", "024d0127"},
    {"message digest", "29750586"},
    {"abcdefghijklmnopqrstuvwxyz", "90860b20"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "8adb150c"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "97b61069"}};

static const std::unordered_map<std::string, std::vector<uint8_t>> byte_data = {
    {"\x2", {0x00, 0x03, 0x00, 0x03}},
    {"\x2\x4", {0x00, 0x0a, 0x00, 0x07}},
    {"", {0x00, 0x00, 0x00, 0x01}},
    {"a", {0x00, 0x62, 0x00, 0x62}},
    {"abc", {0x02, 0x4d, 0x01, 0x27}},
    {"message digest", {0x29, 0x75, 0x05, 0x86}},
    {"abcdefghijklmnopqrstuvwxyz", {0x90, 0x86, 0x0b, 0x20}},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", {0x8a, 0xdb, 0x15, 0x0c}},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", {0x97, 0xb6, 0x10, 0x69}}};

BOOST_AUTO_TEST_SUITE(keccak_test_suite)

BOOST_DATA_TEST_CASE(keccak_1600_range_itr_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out;
    hash<keccak_1600<512>>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(keccak_1600_various_range_value_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out = hash<keccak_1600<512>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(keccak_1600_various_itr_value_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out = hash<keccak_1600<512>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(keccak_1600_iterator_itr_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out;
    hash<keccak_1600<512>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(keccak_1600_string_various_range_value_hash, boost::unit_test::data::make(string_data),
                     array_element) {
    std::string out = hash<keccak_1600<512>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(keccak_1600_string_various_itr_value_hash, boost::unit_test::data::make(string_data),
                     array_element) {
    std::string out = hash<keccak_1600<512>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_SUITE_END()
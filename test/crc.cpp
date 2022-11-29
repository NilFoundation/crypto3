//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE crc_test

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/crc.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/detail/static_digest.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iostream>
#include <string>
#include <cassert>
#include <unordered_map>

using namespace nil::crypto3;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::accumulators;
using nil::crypto3::detail::largest_prime;

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
    {"", "00000000"},
    {"a", "e8b7be43"},
    {"abc", "352441c2"},
    {"message digest", "20159d7f"},
    {"abcdefghijklmnopqrstuvwxyz", "4c2750bd"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "1fc2e6d2"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "7ca94a72"}};

static const std::unordered_map<std::string, std::vector<uint8_t>> byte_data = {
    {"", {0x00, 0x00, 0x00, 0x00}},
    {"a", {0xe8, 0xb7, 0xbe, 0x43}},
    {"abc", {0x35, 0x24, 0x41, 0xc2}},
    {"message digest", {0x20, 0x15, 0x9d, 0x7f}},
    {"abcdefghijklmnopqrstuvwxyz", {0x4c, 0x27, 0x50, 0xbd}},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", {0x1f, 0xc2, 0xe6, 0xd2}},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", {0x7c, 0xa9, 0x4a, 0x72}}};

BOOST_AUTO_TEST_SUITE(crc_hash_test_suite)

BOOST_DATA_TEST_CASE(crc_range_itr_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out;
    hash<hashes::crc32_png>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(crc_various_range_value_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out = hash<hashes::crc32_png>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(crc_various_itr_value_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out = hash<hashes::crc32_png>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(crc_iterator_itr_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out;
    hash<hashes::crc32_png>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(crc_string_various_range_value_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<hashes::crc32_png>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(crc_string_various_itr_value_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<hashes::crc32_png>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_CASE(crc_stateful_hash1) {
    accumulator_set<hashes::crc32_png> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    typename hashes::crc32_png::digest_type d = extract::hash<hashes::crc32_png>(acc);
    std::cout << d << "\n";
    BOOST_CHECK_EQUAL(d, "dc25bfbc");
}

BOOST_AUTO_TEST_CASE(crc_stateful_hash2) {
    accumulator_set<hashes::crc32_png> acc;
    std::string s(1000, 'a');
    for (unsigned i = 0; i < 1000000; ++i) {
        hash<hashes::crc32_png>(s, acc);
    }
    crc32_png::digest_type d = extract::hash<crc32_png>(acc);
    std::cout << d << "\n";
    BOOST_CHECK_EQUAL(d, "a7943e77");
}

BOOST_AUTO_TEST_CASE(crc_stateful_hash3) {
    accumulator_set<hashes::crc32_png> acc;
    for (unsigned i = 0; i < 1000000000; ++i) {
        acc('a');
    }
    crc32_png::digest_type d = extract::hash<hashes::crc32_png>(acc);
    std::cout << d << "\n";
    BOOST_CHECK_EQUAL(d, "a7943e77");
}

BOOST_AUTO_TEST_SUITE_END()
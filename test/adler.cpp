//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE adler_test

#include <nil/crypto3/hash/adler.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/detail/primes.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

using namespace nil::crypto3::hash;
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

BOOST_AUTO_TEST_SUITE(adler_test_suite)

BOOST_AUTO_TEST_CASE(largest_prime_test) {
    BOOST_CHECK_EQUAL(largest_prime<2>::value, 3);
    BOOST_CHECK_EQUAL(largest_prime<3>::value, 7);
    BOOST_CHECK_EQUAL(largest_prime<4>::value, 13);
    BOOST_CHECK_EQUAL(largest_prime<5>::value, 31);
    BOOST_CHECK_EQUAL(largest_prime<6>::value, 61);
    BOOST_CHECK_EQUAL(largest_prime<7>::value, 127);
    BOOST_CHECK_EQUAL(largest_prime<8>::value, 251);
    BOOST_CHECK_EQUAL(largest_prime<9>::value, 509);
    BOOST_CHECK_EQUAL(largest_prime<10>::value, 1021);
    BOOST_CHECK_EQUAL(largest_prime<11>::value, 2039);
    BOOST_CHECK_EQUAL(largest_prime<12>::value, 4093);
    BOOST_CHECK_EQUAL(largest_prime<13>::value, 8191);
    BOOST_CHECK_EQUAL(largest_prime<14>::value, 16381);
    BOOST_CHECK_EQUAL(largest_prime<15>::value, 32749);
    BOOST_CHECK_EQUAL(largest_prime<16>::value, 65521);
    BOOST_CHECK_EQUAL(largest_prime<17>::value, 131071);
    BOOST_CHECK_EQUAL(largest_prime<18>::value, 262139);
    BOOST_CHECK_EQUAL(largest_prime<19>::value, 524287);
    BOOST_CHECK_EQUAL(largest_prime<20>::value, 1048573);
    BOOST_CHECK_EQUAL(largest_prime<21>::value, 2097143);
    BOOST_CHECK_EQUAL(largest_prime<22>::value, 4194301);
    BOOST_CHECK_EQUAL(largest_prime<23>::value, 8388593);
    BOOST_CHECK_EQUAL(largest_prime<24>::value, 16777213);
    BOOST_CHECK_EQUAL(largest_prime<25>::value, 33554393);
    BOOST_CHECK_EQUAL(largest_prime<26>::value, 67108859);
    BOOST_CHECK_EQUAL(largest_prime<27>::value, 134217689);
    BOOST_CHECK_EQUAL(largest_prime<28>::value, 268435399);
    BOOST_CHECK_EQUAL(largest_prime<29>::value, 536870909);
    BOOST_CHECK_EQUAL(largest_prime<30>::value, 1073741789);
    BOOST_CHECK_EQUAL(largest_prime<31>::value, 2147483647);
    BOOST_CHECK_EQUAL(largest_prime<32>::value, 4294967291U);
}

BOOST_DATA_TEST_CASE(adler_range_itr_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out;
    hash<adler<32>>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(adler_various_range_value_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out = hash<adler<32>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(adler_string_range_value_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<adler<32>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(adler_various_itr_value_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out = hash<adler<32>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(adler_string_itr_value_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<adler<32>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(adler_iterator_itr_hash, boost::unit_test::data::make(byte_data), array_element) {
    std::vector<uint8_t> out;
    hash<adler<32>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_CASE(adler_stateful_hash1) {
    accumulator_set<adler<32>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    adler<32>::digest_type d = extract::hash<adler<32>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << d << "\n";
#endif

    BOOST_CHECK_EQUAL(d, "15d870f9");
}

BOOST_AUTO_TEST_CASE(adler_stateful_hash2) {
    accumulator_set<adler<32>> acc;
    std::string s(1000, 'a');
    for (unsigned i = 0; i < 1000000; ++i) {
        hash<adler<32>>(s, acc);
    }
    adler<32>::digest_type d = extract::hash<adler<32>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << d << "\n";
#endif

    BOOST_CHECK_EQUAL(d, "bbc26298");
}

BOOST_AUTO_TEST_CASE(adler_stateful_hash3) {
    accumulator_set<adler<32>> acc;
    for (unsigned i = 0; i < 1000000000; ++i) {
        acc('a');
    }
    adler<32>::digest_type d = extract::hash<adler<32>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << d << "\n";
#endif

    BOOST_CHECK_EQUAL(d, "bbc26298");
}

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE md4_test

//#define CRYPTO3_HASH_SHOW_PROGRESS
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/md4.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <cstdio>
#include <cstring>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(md4::construction_type::digest_type)

static const std::unordered_map<std::string, std::string> string_data = {
    {"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
    {"a", "bde52cb31de33e46245e05fbdbd6fb24"},
    {"abc", "a448017aaf21d8525fc10ae87aa6729d"},
    {"message digest", "d9130a8164549fe818874806e1c7014b"},
    {"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "e33b4ddc9c38f2199c3e7b164fcc0536"}};

BOOST_AUTO_TEST_SUITE(md4_test_suite)

BOOST_DATA_TEST_CASE(md4_return_range_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<md4>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_CASE(md4_accumulator1) {
    hash_accumulator<md4> acc;
    md4::construction_type::digest_type s = extract::hash<md4>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("0123456789abcdeffedcba9876543210", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md4_accumulator2) {
    // 0-length input: echo -n | md4sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0.
    // Remember that MD5 is little-octet, big-bit endian
    hash_accumulator<md4> acc;
    md4::construction_type::block_type m = {{0x00000080u}};
    acc(m);
    md4::construction_type::digest_type s = extract::hash<md4>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("31d6cfe0d16ae931b73c59d7e0c089c0", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md4_accumulator3) {
    // echo -n "abc" | md4sum
    hash_accumulator<md4> acc;
    md4::construction_type::block_type m = {{}};
    m[0] = 0x80636261;
    // little-octet, big-bit endian also means the size isn't in the last word
    m[14] = 0x00000018;
    acc(m);
    md4::construction_type::digest_type s = extract::hash<md4>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("a448017aaf21d8525fc10ae87aa6729d", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md4_preprocessor1) {
    hash_accumulator<md4> acc;
    md4::construction_type::digest_type s = extract::hash<md4>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("31d6cfe0d16ae931b73c59d7e0c089c0", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md4_preprocessor2) {
    hash_accumulator<md4> acc;
    acc('a');
    acc('b');
    acc('c');

    md4::construction_type::digest_type s = extract::hash<md4>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("a448017aaf21d8525fc10ae87aa6729d", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md4_preprocessor3) {
    hash_accumulator<md4> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    md4::construction_type::digest_type s = extract::hash<md4>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("bbce80cc6bb65e5c6745e30d4eeca9a4", std::to_string(s));
}

BOOST_AUTO_TEST_SUITE_END()
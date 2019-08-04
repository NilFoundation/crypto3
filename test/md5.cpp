//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE md5_test

//#define CRYPTO3_HASH_SHOW_PROGRESS
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/md5.hpp>
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

BOOST_TEST_DONT_PRINT_LOG_VALUE(md5::construction_type::digest_type)

static const std::unordered_map<std::string, std::string> string_data = {
    {"", "d41d8cd98f00b204e9800998ecf8427e"},
    {"a", "0cc175b9c0f1b6a831c399e269772661"},
    {"abc", "900150983cd24fb0d6963f7d28e17f72"},
    {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
    {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "57edf4a22be3c955ac49da2e2107b67a"}};

class fixture {
public:
    md5::construction_type a;
};

BOOST_AUTO_TEST_SUITE(md5_test_suite)

BOOST_DATA_TEST_CASE(md5_range_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<md5>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_FIXTURE_TEST_CASE(md5_accumulator1, fixture) {
    md5::construction_type::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("0123456789abcdeffedcba9876543210", std::to_string(s));
    a.reset();
}

BOOST_FIXTURE_TEST_CASE(md5_accumulator2, fixture) {
    // 0-length input: echo -n | md4sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0.
    // Remember that MD5 is little-octet, big-bit endian
    md5::construction_type::block_type m = {{0x00000080u}};
    a(m);
    md5::construction_type::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", std::to_string(s));

    a.reset();
}

BOOST_FIXTURE_TEST_CASE(md5_accumulator3, fixture) {
    // echo -n "abc" | md4sum
    md5::construction_type::block_type m = {{}};
    m[0] = 0x80636261;
    // little-octet, big-bit endian also means the size isn't in the last word
    m[14] = 0x00000018;
    a(m);
    md5::construction_type::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(s));

    a.reset();
}

BOOST_AUTO_TEST_CASE(md5_preprocessor1) {
    hash_accumulator<md5> acc;
    md5::construction_type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor2) {
    hash_accumulator<md5> acc;
    acc('a');
    acc('b');
    acc('c');

    md5::construction_type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | md5sum
    hash_accumulator<md5> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    md5::construction_type::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("7707d6ae4e027c70eea2a935c2296f21", std::to_string(s));
}

BOOST_AUTO_TEST_SUITE_END()
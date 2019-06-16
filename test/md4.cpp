//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
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

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

BOOST_TEST_DONT_PRINT_LOG_VALUE(md4::construction_type::digest_type)

static const std::unordered_map<std::string, std::string> string_data = {{"",                                                                                 "31d6cfe0d16ae931b73c59d7e0c089c0"},
                                                                         {"a",                                                                                "bde52cb31de33e46245e05fbdbd6fb24"},
                                                                         {"abc",                                                                              "a448017aaf21d8525fc10ae87aa6729d"},
                                                                         {"message digest",                                                                   "d9130a8164549fe818874806e1c7014b"},
                                                                         {"abcdefghijklmnopqrstuvwxyz",                                                       "d79e1c308aa5bbcdeea8ed63df412da9"},
                                                                         {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",                   "043f8582f241db351ce627e153e7f0e4"},
                                                                         {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"}};

class fixture {
public:
    fixture() {
        a.reset();
    }

    md4::construction_type a;
};

BOOST_AUTO_TEST_SUITE(md4_test_suite)

    BOOST_DATA_TEST_CASE(md4_return_range_hash, boost::unit_test::data::make(string_data), array_element) {
        std::string out = hash<md4>(array_element.first);

        BOOST_CHECK_EQUAL(out, array_element.second);
    }

    BOOST_FIXTURE_TEST_CASE(md4_accumulator1, fixture) {
        md4::construction_type::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::printf("%s\n", std::to_string(s));
#endif

        BOOST_CHECK_EQUAL("0123456789abcdeffedcba9876543210", std::to_string(s));
        a.reset();
    }

    BOOST_FIXTURE_TEST_CASE(md4_accumulator2, fixture) {
        // 0-length input: echo -n | md4sum

        // A single 1 bit after the (empty) message,
        // then pad with 0s,
        // then add the length, which is also 0.
        // Remember that MD5 is little-octet, big-bit endian
        md4::construction_type::block_type m = {{0x00000080u}};
        a.update(m);
        md4::construction_type::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::printf("%s\n", std::to_string(s));
#endif

        BOOST_CHECK_EQUAL("31d6cfe0d16ae931b73c59d7e0c089c0", std::to_string(s));

        a.reset();
    }

    BOOST_FIXTURE_TEST_CASE(md4_accumulator3, fixture) {
        // echo -n "abc" | md4sum
        md4::construction_type::block_type m = {{}};
        m[0] = 0x80636261;
        // little-octet, big-bit endian also means the size isn't in the last word
        m[14] = 0x00000018;
        a.update(m);
        md4::construction_type::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::printf("%s\n", std::to_string(s));
#endif

        BOOST_CHECK_EQUAL("a448017aaf21d8525fc10ae87aa6729d", std::to_string(s));

        a.reset();
    }

    BOOST_AUTO_TEST_CASE(md4_preprocessor1) {
        md4::stream_processor<8>::type h;
        md4::construction_type::digest_type s = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::printf("%s\n", std::to_string(s));
#endif

        BOOST_CHECK_EQUAL("31d6cfe0d16ae931b73c59d7e0c089c0", std::to_string(s));
    }

    BOOST_AUTO_TEST_CASE(md4_preprocessor2) {
        md4::stream_processor<8>::type h;
        h.update_one('a').update_one('b').update_one('c');
        BOOST_CHECK(h.digest() == h.digest());

        md4::construction_type::digest_type s = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::printf("%s\n", std::to_string(s));
#endif

        BOOST_CHECK_EQUAL("a448017aaf21d8525fc10ae87aa6729d", std::to_string(s));
    }

    BOOST_AUTO_TEST_CASE(md4_preprocessor3) {
        md4::stream_processor<8>::type h;
        for (unsigned i = 0; i < 1000000; ++i) {
            h.update_one('a');
        }
        md4::construction_type::digest_type s = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::printf("%s\n", std::to_string(s));
#endif

        BOOST_CHECK_EQUAL("bbce80cc6bb65e5c6745e30d4eeca9a4", std::to_string(s));
    }

BOOST_AUTO_TEST_SUITE_END()
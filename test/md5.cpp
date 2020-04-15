//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE md5_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(md5::construction::type::digest_type)

class fixture {
public:
    accumulator_set<md5> acc;
    virtual ~fixture() {
    }
};

static const std::unordered_map<std::string, std::string> string_data = {
    {"a", "0cc175b9c0f1b6a831c399e269772661"},
    {"\x24", "c3e97dd6e97fb5125688c97f36720cbe"},
    {"abc", "900150983cd24fb0d6963f7d28e17f72"},
    {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
    {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
    {"The quick brown fox jumped over the lazy dog's back","e38ca1d920c4b8b8d3946b2c72f01680"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","8215ef0796a20bcaaae116d3876c664a"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "57edf4a22be3c955ac49da2e2107b67a"}};


BOOST_AUTO_TEST_SUITE(md5_stream_processor_test_suite)

BOOST_DATA_TEST_CASE(md5_range_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = hash<md5>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_CASE(md5_shortmsg_byte1) {
    // echo -n "a" | md5sum 
    std::array<char, 1> a = {'\x61'};
    md5::digest_type d = hash<md5>(a);

    BOOST_CHECK_EQUAL("0cc175b9c0f1b6a831c399e269772661", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(md5_shortmsg_byte2) {
    // echo -n "abc" | md5sum 
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    md5::digest_type d = hash<md5>(a);

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(md5_shortmsg_byte3) {
    // echo -n "message digest" | md5sum
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65', '\x20', '\x64', '\x69', '\x67', 
                             '\x65', '\x73', '\x74'};
    md5::digest_type d = hash<md5>(a);

    BOOST_CHECK_EQUAL("f96b697d7cb7938d525a2f31aaf161d0", std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(md5_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(md5_accumulator1, fixture) {
    // echo -n "a" | md5sum
    md5::block_type m = {{}};
    m[0] = 0x00000061;
    acc(m, nil::crypto3::accumulators::bits = 8);
    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("0cc175b9c0f1b6a831c399e269772661", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(md5_accumulator2, fixture) {
    // echo -n "abc" | md5sum
    md5::block_type m = {{}};
    m[0] = 0x00636261;
    acc(m, nil::crypto3::accumulators::bits = 24);
    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(md5_accumulator3, fixture) {
    // 80 times of \xa3
    md5::block_type m1 = {
        {0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 
         0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 
         0x000102a3, 0x67283609}};
    acc(m1, nil::crypto3::accumulators::bits = 14 * 32 + 8);

    md5::digest_type s = extract::hash<md5>(acc);

    BOOST_CHECK_EQUAL("2d8dc29362bb044de17c01817e0b6808", std::to_string(s).data());

    md5::construction::type::block_type m2 = {
        {0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0xa3a3a3a3, 0x00a3a3a3, 0x82934724, 
         0xa0a93453, 0x293c203d, 0x6e6f7071, 0x6f707172, 0x70717273, 0x71727374, 0x72737475, 
         0x00000000, 0x00000000}};

    acc(m2, nil::crypto3::accumulators::bits = 6 * 32 - 8);

    s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("4229f60b21858cbd30d41b3ad26cb274", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(md5_preprocessor1) {
    accumulator_set<md5> acc;
    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("d41d8cd98f00b204e9800998ecf8427e", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor2) {
    accumulator_set<md5> acc;
    acc(0x00000061, nil::crypto3::accumulators::bits = 8);
    acc(0x00000062, nil::crypto3::accumulators::bits = 8);
    acc(0x00000063, nil::crypto3::accumulators::bits = 8);

    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("900150983cd24fb0d6963f7d28e17f72", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | md5sum
    accumulator_set<md5> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc(0x00000061, nil::crypto3::accumulators::bits = 8);
    }
    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("7707d6ae4e027c70eea2a935c2296f21", std::to_string(s));
}

BOOST_AUTO_TEST_CASE(md5_preprocessor4) {
    //  perl -e 'for (1..8) { print "1234567890"; }' | md5sum
    accumulator_set<md5> acc;
    for (unsigned i = 0; i < 8; ++i) {
        acc(0x00000031, nil::crypto3::accumulators::bits = 8);
        acc(0x00000032, nil::crypto3::accumulators::bits = 8);
        acc(0x00000033, nil::crypto3::accumulators::bits = 8);
        acc(0x00000034, nil::crypto3::accumulators::bits = 8);
        acc(0x00000035, nil::crypto3::accumulators::bits = 8);
        acc(0x00000036, nil::crypto3::accumulators::bits = 8);
        acc(0x00000037, nil::crypto3::accumulators::bits = 8);
        acc(0x00000038, nil::crypto3::accumulators::bits = 8);
        acc(0x00000039, nil::crypto3::accumulators::bits = 8);
        acc(0x00000030, nil::crypto3::accumulators::bits = 8);
    }
    md5::digest_type s = extract::hash<md5>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("57edf4a22be3c955ac49da2e2107b67a", std::to_string(s));
}

BOOST_AUTO_TEST_SUITE_END()
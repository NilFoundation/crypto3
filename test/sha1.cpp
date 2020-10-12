//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#define BOOST_TEST_MODULE sha1_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/sha1.hpp>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha1::construction::type::digest_type)

class fixture {
public:
    accumulator_set<hashes::sha1> acc;
    typedef hashes::sha1 hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/sha1.json";

boost::property_tree::ptree string_data() {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(sha1_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(sha1_string_various_range_value_hash, string_data(), array_element) {
    std::string out = hash<hashes::sha1>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha1_string_various_itr_value_hash, string_data(), array_element) {
    std::string out = hash<hashes::sha1>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha1_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(sha1_string_various_range_value_hash, string_data(), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::sha1>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha1_stream_processor_test_suite)

BOOST_AUTO_TEST_CASE(sha1_shortmsg_byte1) {
    // echo -n "a" | sha1sum
    std::array<char, 1> a = {'\x61'};
    hashes::sha1::digest_type d = hash<hashes::sha1>(a);

    BOOST_CHECK_EQUAL("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha1_shortmsg_byte2) {
    // echo -n "abc" | sha1sum
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::sha1::digest_type d = hash<hashes::sha1>(a);

    BOOST_CHECK_EQUAL("a9993e364706816aba3e25717850c26c9cd0d89d", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha1_shortmsg_byte3) {
    // echo -n "message digest" | sha1sum
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::sha1::digest_type d = hash<hashes::sha1>(a);

    BOOST_CHECK_EQUAL("c12252ceda8be8994d5fa0290a47231c1d16aae3", std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha1_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(sha1_accumulator1, fixture) {
    // echo -n "a" | sha1sum
    hash_t::construction::type::block_type m = {{}};

    m[0] = 0x61000000;
    acc(m, accumulators::bits = 8);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator2, fixture) {
    // echo -n "abc" | sha1sum
    hash_t::construction::type::block_type m = {{}};

    m[0] = 0x61626300;
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("a9993e364706816aba3e25717850c26c9cd0d89d", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator3, fixture) {
    // echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha1sum
    hash_t::construction::type::block_type m1 = {
        {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d010101, 0x01010101, 0x80000000, 0x00000000}};
    acc(m1, accumulators::bits = 512 - 64 - 64 + 8);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL("9d47791975c530645ad3568e80f88d7da4c52c3b", std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {0x6e6f706e, 0x6f707100, 0x6d6e6f70, 0x6e6f7071, 0x6d6e6f70, 0x6e6f7071, 0x0168696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d010170, 0x6e6f7071, 0x80080000, 0x00000000}};

    acc(m2, accumulators::bits = 64 - 8);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("84983e441c3bd26ebaae4aa1f95129e5e54670f1", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator4, fixture) {
    // echo -n "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn (continues)
    //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" | sha1sum
    hash_t::construction::type::block_type m1 = {
        {0x61626364, 0x65666768, 0x62636465, 0x66676869, 0x63646566, 0x6768696a, 0x64656667, 0x68696a6b, 0x65666768,
         0x696a6b6c, 0x66676869, 0x6a6b6c6d, 0x6768696a, 0x6b6c6d6e, 0x68696a6b, 0x6c6d6e6f}};
    acc(m1, accumulators::bits = 512);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL("b85d6468bd3a73794bceaf812239cc1fe460ab95", std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {0x696a6b6c, 0x6d6e6f70, 0x6a6b6c6d, 0x6e6f7071, 0x6b6c6d6e, 0x6f707172, 0x6c6d6e6f, 0x70717273, 0x6d6e6f70,
         0x71727374, 0x6e6f7071, 0x72737475, 0x6d010170, 0x6e6f7071, 0x80080000, 0x00000000}};

    acc(m2, accumulators::bits = 64 * 6);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("a49b2446a02c645bf419f995b67091253a04a259", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha1_preprocessor1) {
    accumulator_set<hashes::sha1> acc;
    hashes::sha1::digest_type s = extract::hash<hashes::sha1>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha1_preprocessor2) {
    accumulator_set<hashes::sha1> acc;

    acc(0x61000000, accumulators::bits = 8);
    acc(0x62000000, accumulators::bits = 8);
    acc(0x63000000, accumulators::bits = 8);

    hashes::sha1::digest_type s = extract::hash<hashes::sha1>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("a9993e364706816aba3e25717850c26c9cd0d89d", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha1_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | sha1sum
    accumulator_set<hashes::sha1> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(0x61000000, accumulators::bits = 8);

    hashes::sha1::digest_type s = extract::hash<hashes::sha1>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("34aa973cd4c4daa4f61eeb2bdbad27316534016f", std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()
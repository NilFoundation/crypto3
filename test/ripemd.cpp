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

#define BOOST_TEST_MODULE ripemd_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/ripemd.hpp>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::ripemd<128>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::ripemd<160>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::ripemd<256>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::ripemd<320>::construction::type::digest_type)

template<std::size_t Size>
class fixture {
public:
    accumulator_set<hashes::ripemd<Size>> acc;
    typedef hashes::ripemd<Size> hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/ripemd.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(ripemd_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(ripemd_128_range_hash, string_data("data_128"), array_element) {
    std::string out = hash<hashes::ripemd<128>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_160_range_hash, string_data("data_160"), array_element) {
    std::string out = hash<hashes::ripemd<160>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_256_range_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::ripemd<256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_320_range_hash, string_data("data_320"), array_element) {
    std::string out = hash<hashes::ripemd<320>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_128_typedef_range_hash, string_data("data_128"), array_element) {
    std::string out = hash<hashes::ripemd128>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_160_typedef_range_hash, string_data("data_160"), array_element) {
    std::string out = hash<hashes::ripemd160>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_256_typedef_range_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::ripemd256>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_320_typedef_range_hash, string_data("data_320"), array_element) {
    std::string out = hash<hashes::ripemd320>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ripemd_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(ripemd_128_range_hash, string_data("data_128"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd<128>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_160_range_hash, string_data("data_160"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd<160>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_256_range_hash, string_data("data_256"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd<256>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_320_range_hash, string_data("data_320"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd<320>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_128_typedef_range_hash, string_data("data_128"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd128>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_160_typedef_range_hash, string_data("data_160"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd160>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_256_typedef_range_hash, string_data("data_256"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd256>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(ripemd_320_typedef_range_hash, string_data("data_320"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::ripemd320>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ripemd_stream_processor_test_suite)

BOOST_AUTO_TEST_CASE(ripemd_128_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::ripemd<128>::digest_type d = hash<hashes::ripemd<128>>(a);

    BOOST_CHECK_EQUAL("86be7afa339d0fc7cfc785e72f578d33", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_128_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::ripemd<128>::digest_type d = hash<hashes::ripemd<128>>(a);

    BOOST_CHECK_EQUAL("c14a12199c66e4ba84636b0f69144c77", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_128_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::ripemd<128>::digest_type d = hash<hashes::ripemd<128>>(a);

    BOOST_CHECK_EQUAL("9e327b3d6e523062afc1132d7df9d1b8", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_160_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::ripemd<160>::digest_type d = hash<hashes::ripemd<160>>(a);

    BOOST_CHECK_EQUAL("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_160_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::ripemd<160>::digest_type d = hash<hashes::ripemd<160>>(a);

    BOOST_CHECK_EQUAL("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_160_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::ripemd<160>::digest_type d = hash<hashes::ripemd<160>>(a);

    BOOST_CHECK_EQUAL("5d0689ef49d2fae572b881b123a85ffa21595f36", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_256_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::ripemd<256>::digest_type d = hash<hashes::ripemd<256>>(a);

    BOOST_CHECK_EQUAL("f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_256_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::ripemd<256>::digest_type d = hash<hashes::ripemd<256>>(a);

    BOOST_CHECK_EQUAL("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_256_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::ripemd<256>::digest_type d = hash<hashes::ripemd<256>>(a);

    BOOST_CHECK_EQUAL("87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_320_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::ripemd<320>::digest_type d = hash<hashes::ripemd<320>>(a);

    BOOST_CHECK_EQUAL(
        "ce78850638f92658a5a585097579926dda667a57"
        "16562cfcf6fbe77f63542f99b04705d6970dff5d",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_320_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::ripemd<320>::digest_type d = hash<hashes::ripemd<320>>(a);

    BOOST_CHECK_EQUAL(
        "de4c01b3054f8930a79d09ae738e92301e5a1708"
        "5beffdc1b8d116713e74f82fa942d64cdbc4682d",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(ripemd_320_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::ripemd<320>::digest_type d = hash<hashes::ripemd<320>>(a);

    BOOST_CHECK_EQUAL(
        "3a8e28502ed45d422f68844f9dd316e7b98533fa"
        "3f2a91d29f84d425c88d6b4eff727df66a7c0197",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ripemd_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(ripemd_128_accumulator1, fixture<128>) {
    // "a"
    hashes::ripemd<128>::block_type m = {{}};
    m[0] = 0x00000061;
    acc(m, accumulators::bits = 8);
    hashes::ripemd<128>::digest_type s = extract::hash<hashes::ripemd<128>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("86be7afa339d0fc7cfc785e72f578d33", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_128_accumulator2, fixture<128>) {
    // "abc"
    hashes::ripemd<128>::block_type m = {{}};
    m[0] = 0x00636261;
    acc(m, accumulators::bits = 24);
    hashes::ripemd<128>::digest_type s = extract::hash<hashes::ripemd<128>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("c14a12199c66e4ba84636b0f69144c77", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_128_accumulator3, fixture<128>) {
    // 80 times of "a"
    hashes::ripemd<128>::block_type m1 = {{0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x00010261, 0x67283609}};

    acc(m1, accumulators::bits = 14 * 32 + 8);

    hashes::ripemd<128>::digest_type s = extract::hash<hashes::ripemd<128>>(acc);

    BOOST_CHECK_EQUAL("d6a7de242c383193285db1de0459c32c", std::to_string(s).data());

    hashes::ripemd<128>::construction::type::block_type m2 = {
        {0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x00616161, 0x82934724, 0xa0a93453, 0x293c203d,
         0x6e6f7071, 0x6f707172, 0x70717273, 0x71727374, 0x72737475, 0x00000000, 0x00000000}};

    acc(m2, accumulators::bits = 6 * 32 - 8);

    s = extract::hash<hashes::ripemd<128>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("d7fc37ea6df34cb33825447bf29abbb9", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_160_accumulator1, fixture<160>) {
    // "a"
    hashes::ripemd<160>::block_type m = {{}};
    m[0] = 0x00000061;
    acc(m, accumulators::bits = 8);
    hashes::ripemd<160>::digest_type s = extract::hash<hashes::ripemd<160>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_160_accumulator2, fixture<160>) {
    // "abc"
    hashes::ripemd<160>::block_type m = {{}};
    m[0] = 0x00636261;
    acc(m, accumulators::bits = 24);
    hashes::ripemd<160>::digest_type s = extract::hash<hashes::ripemd<160>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_160_accumulator3, fixture<160>) {
    // 80 times of "a"
    hashes::ripemd<160>::block_type m1 = {{0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x00010261, 0x67283609}};

    acc(m1, accumulators::bits = 14 * 32 + 8);

    hashes::ripemd<160>::digest_type s = extract::hash<hashes::ripemd<160>>(acc);

    BOOST_CHECK_EQUAL("eed82d19d597ab275b550ff3d6e0bc2a75350388", std::to_string(s).data());

    hashes::ripemd<160>::construction::type::block_type m2 = {
        {0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x00616161, 0x82934724, 0xa0a93453, 0x293c203d,
         0x6e6f7071, 0x6f707172, 0x70717273, 0x71727374, 0x72737475, 0x00000000, 0x00000000}};

    acc(m2, accumulators::bits = 6 * 32 - 8);

    s = extract::hash<hashes::ripemd<160>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("228d437346bbf829f53490e0a5ef176c5068163f", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_256_accumulator1, fixture<256>) {
    // "a"
    hashes::ripemd<256>::block_type m = {{}};
    m[0] = 0x00000061;
    acc(m, accumulators::bits = 8);
    hashes::ripemd<256>::digest_type s = extract::hash<hashes::ripemd<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_256_accumulator2, fixture<256>) {
    // "abc"
    hashes::ripemd<256>::block_type m = {{}};
    m[0] = 0x00636261;
    acc(m, accumulators::bits = 24);
    hashes::ripemd<256>::digest_type s = extract::hash<hashes::ripemd<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_256_accumulator3, fixture<256>) {
    // 80 times of "a"
    hashes::ripemd<256>::block_type m1 = {{0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x00010261, 0x67283609}};

    acc(m1, accumulators::bits = 14 * 32 + 8);

    hashes::ripemd<256>::digest_type s = extract::hash<hashes::ripemd<256>>(acc);

    BOOST_CHECK_EQUAL("b01629f9a960bbb1aa2a9e0e74319909a9f839570b1c932e59a382923bae1812", std::to_string(s).data());

    hashes::ripemd<256>::construction::type::block_type m2 = {
        {0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x00616161, 0x82934724, 0xa0a93453, 0x293c203d,
         0x6e6f7071, 0x6f707172, 0x70717273, 0x71727374, 0x72737475, 0x00000000, 0x00000000}};

    acc(m2, accumulators::bits = 6 * 32 - 8);

    s = extract::hash<hashes::ripemd<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("e6676aa1b6c0da12250437daec6af99857923fe3cef841c2385a851a869e234a", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_320_accumulator1, fixture<320>) {
    // "a"
    hashes::ripemd<320>::block_type m = {{}};
    m[0] = 0x00000061;
    acc(m, accumulators::bits = 8);
    hashes::ripemd<320>::digest_type s = extract::hash<hashes::ripemd<320>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL(
        "ce78850638f92658a5a585097579926dda667a57"
        "16562cfcf6fbe77f63542f99b04705d6970dff5d",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_320_accumulator2, fixture<320>) {
    // "abc"
    hashes::ripemd<320>::block_type m = {{}};
    m[0] = 0x00636261;
    acc(m, accumulators::bits = 24);
    hashes::ripemd<320>::digest_type s = extract::hash<hashes::ripemd<320>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL(
        "de4c01b3054f8930a79d09ae738e92301e5a1708"
        "5beffdc1b8d116713e74f82fa942d64cdbc4682d",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(ripemd_320_accumulator3, fixture<320>) {
    // 80 times of "a"
    hashes::ripemd<320>::block_type m1 = {{0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
                                           0x61616161, 0x61616161, 0x00010261, 0x67283609}};

    acc(m1, accumulators::bits = 14 * 32 + 8);

    hashes::ripemd<320>::digest_type s = extract::hash<hashes::ripemd<320>>(acc);

    BOOST_CHECK_EQUAL(
        "2c38e9ceaad3a53d60f0e38db6d1d4d21d711596"
        "55185b7fa1b85f351c503cdac99f12f583a833a3",
        std::to_string(s).data());

    hashes::ripemd<320>::construction::type::block_type m2 = {
        {0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x00616161, 0x82934724, 0xa0a93453, 0x293c203d,
         0x6e6f7071, 0x6f707172, 0x70717273, 0x71727374, 0x72737475, 0x00000000, 0x00000000}};

    acc(m2, accumulators::bits = 6 * 32 - 8);

    s = extract::hash<hashes::ripemd<320>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "bfe9b13c79cefa874b7deba22e653a8826f0d769"
        "fb8cecf05c90bfe5ba3a19967ce5a7cc65c0c584",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_128_preprocessor1) {
    accumulator_set<hashes::ripemd<128>> acc;
    hashes::ripemd<128>::digest_type s = extract::hash<hashes::ripemd<128>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("cdf26213a150dc3ecb610f18f6b38b46", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_128_preprocessor2) {
    accumulator_set<hashes::ripemd<128>> acc;

    acc(0x00000061, accumulators::bits = 8);
    acc(0x00000062, accumulators::bits = 8);
    acc(0x00000063, accumulators::bits = 8);

    hashes::ripemd<128>::digest_type s = extract::hash<hashes::ripemd<128>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("c14a12199c66e4ba84636b0f69144c77", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_160_preprocessor1) {
    accumulator_set<hashes::ripemd<160>> acc;
    hashes::ripemd<160>::digest_type s = extract::hash<hashes::ripemd<160>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("9c1185a5c5e9fc54612808977ee8f548b2258d31", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_160_preprocessor2) {
    accumulator_set<hashes::ripemd<160>> acc;

    acc(0x00000061, accumulators::bits = 8);
    acc(0x00000062, accumulators::bits = 8);
    acc(0x00000063, accumulators::bits = 8);

    hashes::ripemd<160>::digest_type s = extract::hash<hashes::ripemd<160>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_160_preprocessor3) {
    // million repetitions of "a"
    accumulator_set<hashes::ripemd<160>> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(0x00000061, accumulators::bits = 8);

    hashes::ripemd<160>::digest_type s = extract::hash<hashes::ripemd<160>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("52783243c1697bdbe16d37f97f68f08325dc1528", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_256_preprocessor1) {
    accumulator_set<hashes::ripemd<256>> acc;
    hashes::ripemd<256>::digest_type s = extract::hash<hashes::ripemd<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_256_preprocessor2) {
    accumulator_set<hashes::ripemd<256>> acc;

    acc(0x00000061, accumulators::bits = 8);
    acc(0x00000062, accumulators::bits = 8);
    acc(0x00000063, accumulators::bits = 8);

    hashes::ripemd<256>::digest_type s = extract::hash<hashes::ripemd<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_320_preprocessor1) {
    accumulator_set<hashes::ripemd<320>> acc;
    hashes::ripemd<320>::digest_type s = extract::hash<hashes::ripemd<320>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "22d65d5661536cdc75c1fdf5c6de7b41b9f27325"
        "ebc61e8557177d705a0ec880151c3a32a00899b8",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(ripemd_320_preprocessor2) {
    accumulator_set<hashes::ripemd<320>> acc;

    acc(0x00000061, accumulators::bits = 8);
    acc(0x00000062, accumulators::bits = 8);
    acc(0x00000063, accumulators::bits = 8);

    hashes::ripemd<320>::digest_type s = extract::hash<hashes::ripemd<320>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "de4c01b3054f8930a79d09ae738e92301e5a1708"
        "5beffdc1b8d116713e74f82fa942d64cdbc4682d",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()

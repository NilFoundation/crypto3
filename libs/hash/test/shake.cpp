//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE shake_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/shake.hpp>

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
    }    // namespace test_tools
}    // namespace boost

// template<std::size_t Version = 256, std::size_t Size>
// class fixture {
// public:
//     accumulator_set<hashes::shake<Version, Size>> acc;
//     typedef hashes::shake<Version, Size> hash_t;

//     virtual ~fixture() {
//     }
// };

const char *test_data = TEST_DATA;

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(shake_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(shake_128_range_hash, string_data("data_128"), array_element) {
    std::string out = hash<hashes::shake<128, 256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(shake_128_string_various_itr_value_hash, string_data("data_128"), array_element) {
    std::string out = hash<hashes::shake<128, 256>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(shake_256_string_various_range_value_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::shake<256, 256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(shake_256_string_various_itr_value_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::shake<256, 256>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(shake_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(shake_128_range_hash, string_data("data_128"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::shake<128, 256>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(shake_256_string_various_range_value_hash, string_data("data_256"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::shake<256, 256>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(shake_stream_processor_test_suite)

/* BOOST_AUTO_TEST_CASE(shake_128_shortmsg_bit1) {
    // Known-answer test from https://keccak.team/archives.html
    // Len = 5, Msg = 48
    std::array<bool, 5> a = {0, 1, 0, 0, 1};
    hashes::shake<128>::digest_type d = hashes<hashes::shake<128>>(a);

    BOOST_CHECK_EQUAL("e4384016d64610d75e0a5d73821a02d524e847a25a571b5940cd6450", std::to_string(d).data());
}*/

BOOST_AUTO_TEST_CASE(shake_128_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::shake<128, 128>::digest_type d = hash<hashes::shake<128, 128>>(a);

    BOOST_CHECK_EQUAL("85c8de88d28866bf0868090b3961162b", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shake_128_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::shake<128, 256>::digest_type d = hash<hashes::shake<128, 256>>(a);

    BOOST_CHECK_EQUAL("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shake_128_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::shake<128, 384>::digest_type d = hash<hashes::shake<128, 384>>(a);

    BOOST_CHECK_EQUAL(
        "cbef732961b55b4c31396796577df491b6eed61d8949ce967226801e411e53f09544c13fe4df40fc8df5f9853e8541d0",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shake_256_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::shake<256, 256>::digest_type d = hash<hashes::shake<256, 256>>(a);

    BOOST_CHECK_EQUAL("867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042530ba4", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shake_256_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::shake<256, 512>::digest_type d = hash<hashes::shake<256, 512>>(a);

    BOOST_CHECK_EQUAL(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a"
        "4feb06bd8801e751e4",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shake_256_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::shake<256, 768>::digest_type d = hash<hashes::shake<256, 768>>(a);

    BOOST_CHECK_EQUAL(
        "718e224088856840ade4dc73487e15826a07ecb8ed5e2bda526cc1acddb99d006049815844be0c6c29b759db80b7daa684cb46d90f7eef"
        "107d24aafcfaf0dacaca2888dfaa737694bc46d5c95f17c5cfe7b0c95cfd6a126dd9640c8e62e5ad1c",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shake_256_shortmsg_byte4) {
    // "message digest"
    std::array<char, 1> a = {'\x61'};
    hashes::shake<256, 2048>::digest_type d = hash<hashes::shake<256, 2048>>(a);

    BOOST_CHECK_EQUAL(
        "867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042530ba436b7b1ec0e06a279bc790733bb0aee6fa802683c7b3550"
        "63c434e91189b0c651d092b01e55ce4d610b54a5466d02f88fc378096fb0dad0254857fe1e6381abc04e07e33d916935935636004896c5"
        "b1253464f1cb5ea73b007bc5028bbbea13ebc28668dbfc26b1240ce4239f8d50627ddaa01641dfeaa9d2fef03dd025e0b82cf071fb9ca3"
        "232c742d836b3cbcc8c3cba5b058b76795c177012314196dc822768991c0f16f8a655a731fd37ec92460d61ea722e2723c8681235c4cfa"
        "70fdddfeefac1a892d652cfbaa02b138e3b2d050d550f0c977c024bc2aab0c3456a6afef",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(shake_accumulator_test_suite)

// BOOST_FIXTURE_TEST_CASE(shake_128_accumulator, fixture<128>) {
//     // "abc"
//     hash_t::construction::type::block_type m = {{}};

//     m[0] = UINT64_C(0x0000000000636261);
//     acc(m, accumulators::bits = 24);

//     hash_t::digest_type s = extract::hash<hash_t>(acc);

// #ifdef CRYPTO3_HASH_SHOW_PROGRESS
//     std::printf("%s\n", std::to_string(s).data());
// #endif

//     BOOST_CHECK_EQUAL("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8", std::to_string(s).data());
// }

// BOOST_FIXTURE_TEST_CASE(shake_256_accumulator, fixture<256>) {
//     // "abc"
//     hash_t::construction::type::block_type m = {{}};

//     m[0] = UINT64_C(0x0000000000636261);
//     acc(m, accumulators::bits = 24);

//     hash_t::digest_type s = extract::hash<hash_t>(acc);

// #ifdef CRYPTO3_HASH_SHOW_PROGRESS
//     std::printf("%s\n", std::to_string(s).data());
// #endif

//     BOOST_CHECK_EQUAL("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", std::to_string(s).data());
// }

// BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(shake_preprocessor_test_suite)

// BOOST_AUTO_TEST_CASE(shake_128_preprocessor1) {
//     accumulator_set<hashes::shake<128>> acc;
//     hashes::shake<128>::digest_type s = extract::hash<hashes::shake<128>>(acc);

// #ifdef CRYPTO3_HASH_SHOW_PROGRESS
//     std::printf("%s\n", std::to_string(s).data());
// #endif

//     BOOST_CHECK_EQUAL("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", std::to_string(s).data());
// }

// BOOST_AUTO_TEST_CASE(shake_128_preprocessor2) {
//     accumulator_set<hashes::shake<128>> acc;

//     acc(UINT64_C(0x0000000000000061), accumulators::bits = 8);
//     acc(UINT64_C(0x0000000000000062), accumulators::bits = 8);
//     acc(UINT64_C(0x0000000000000063), accumulators::bits = 8);

//     hashes::shake<128>::digest_type s = extract::hash<hashes::shake<128>>(acc);

// #ifdef CRYPTO3_HASH_SHOW_PROGRESS
//     std::printf("%s\n", std::to_string(s).data());
// #endif

//     BOOST_CHECK_EQUAL("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8", std::to_string(s).data());
// }

// BOOST_AUTO_TEST_CASE(shake_256_preprocessor1) {
//     accumulator_set<hashes::shake<256>> acc;
//     hashes::shake<256>::digest_type s = extract::hash<hashes::shake<256>>(acc);

// #ifdef CRYPTO3_HASH_SHOW_PROGRESS
//     std::printf("%s\n", std::to_string(s).data());
// #endif

//     BOOST_CHECK_EQUAL("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", std::to_string(s).data());
// }

// BOOST_AUTO_TEST_CASE(shake_256_preprocessor2) {
//     accumulator_set<hashes::shake<256>> acc;

//     acc(UINT64_C(0x0000000000000061), accumulators::bits = 8);
//     acc(UINT64_C(0x0000000000000062), accumulators::bits = 8);
//     acc(UINT64_C(0x0000000000000063), accumulators::bits = 8);

//     hashes::shake<256>::digest_type s = extract::hash<hashes::shake<256>>(acc);

// #ifdef CRYPTO3_HASH_SHOW_PROGRESS
//     std::printf("%s\n", std::to_string(s).data());
// #endif

//     BOOST_CHECK_EQUAL("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", std::to_string(s).data());
// }

// BOOST_AUTO_TEST_SUITE_END()

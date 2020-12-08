//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE keccak_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/keccak.hpp>

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

template<std::size_t Size>
class fixture {
public:
    accumulator_set<hashes::keccak_1600<Size>> acc;
    typedef hashes::keccak_1600<Size> hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/keccak.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(keccak_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(keccak_224_range_hash, string_data("data_224"), array_element) {
    std::string out = hash<hashes::keccak_1600<224>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_224_string_various_itr_value_hash, string_data("data_224"), array_element) {
    std::string out = hash<hashes::keccak_1600<224>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_256_string_various_range_value_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::keccak_1600<256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_256_string_various_itr_value_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::keccak_1600<256>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_384_string_various_range_value_hash, string_data("data_384"), array_element) {
    std::string out = hash<hashes::keccak_1600<384>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_384_string_various_itr_value_hash, string_data("data_384"), array_element) {
    std::string out = hash<hashes::keccak_1600<384>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_512_string_various_range_value_hash, string_data("data_512"), array_element) {
    std::string out = hash<hashes::keccak_1600<512>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_512_string_various_itr_value_hash, string_data("data_512"), array_element) {
    std::string out = hash<hashes::keccak_1600<512>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(keccak_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(keccak_224_range_hash, string_data("data_224"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::keccak_1600<224>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_256_string_various_range_value_hash, string_data("data_256"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::keccak_1600<256>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_384_string_various_range_value_hash, string_data("data_384"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::keccak_1600<384>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(keccak_512_string_various_range_value_hash, string_data("data_512"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::keccak_1600<512>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(keccak_stream_processor_test_suite)

/* BOOST_AUTO_TEST_CASE(keccak_224_shortmsg_bit1) {
    // Known-answer test from https://keccak.team/archives.html
    // Len = 5, Msg = 48
    std::array<bool, 5> a = {0, 1, 0, 0, 1};
    hashes::keccak_1600<224>::digest_type d = hashes<hashes::keccak_1600<224>>(a);

    BOOST_CHECK_EQUAL("e4384016d64610d75e0a5d73821a02d524e847a25a571b5940cd6450", std::to_string(d).data());
}*/

BOOST_AUTO_TEST_CASE(keccak_224_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::keccak_1600<224>::digest_type d = hash<hashes::keccak_1600<224>>(a);

    BOOST_CHECK_EQUAL("7cf87d912ee7088d30ec23f8e7100d9319bff090618b439d3fe91308", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_224_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::keccak_1600<224>::digest_type d = hash<hashes::keccak_1600<224>>(a);

    BOOST_CHECK_EQUAL("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_224_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::keccak_1600<224>::digest_type d = hash<hashes::keccak_1600<224>>(a);

    BOOST_CHECK_EQUAL("b53b2cd638f440fa49916036acdb22245673992fb1b1963b96fb9e93", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_256_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::keccak_1600<256>::digest_type d = hash<hashes::keccak_1600<256>>(a);

    BOOST_CHECK_EQUAL("3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_256_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::keccak_1600<256>::digest_type d = hash<hashes::keccak_1600<256>>(a);

    BOOST_CHECK_EQUAL("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_256_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::keccak_1600<256>::digest_type d = hash<hashes::keccak_1600<256>>(a);

    BOOST_CHECK_EQUAL("856ab8a3ad0f6168a4d0ba8d77487243f3655db6fc5b0e1669bc05b1287e0147", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_384_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::keccak_1600<384>::digest_type d = hash<hashes::keccak_1600<384>>(a);

    BOOST_CHECK_EQUAL(
        "85e964c0843a7ee32e6b5889d50e130e6485cffc826a30167d1dc2b3a0cc79cb"
        "a303501a1eeaba39915f13baab5abacf",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_384_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::keccak_1600<384>::digest_type d = hash<hashes::keccak_1600<384>>(a);

    BOOST_CHECK_EQUAL(
        "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
        "f8c681e4afaf31a34db29fb763e3c28e",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_384_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::keccak_1600<384>::digest_type d = hash<hashes::keccak_1600<384>>(a);

    BOOST_CHECK_EQUAL(
        "8a377db088c43e44040a2bfb26676704999d90527913cabff0a3484825daa54d"
        "3061e67da7d836a0805356962af310e8",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_512_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::keccak_1600<512>::digest_type d = hash<hashes::keccak_1600<512>>(a);

    BOOST_CHECK_EQUAL(
        "9c46dbec5d03f74352cc4a4da354b4e9796887eeb66ac292617692e765dbe400"
        "352559b16229f97b27614b51dbfbbb14613f2c10350435a8feaf53f73ba01c7c",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_512_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::keccak_1600<512>::digest_type d = hash<hashes::keccak_1600<512>>(a);

    BOOST_CHECK_EQUAL(
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
        "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(keccak_512_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::keccak_1600<512>::digest_type d = hash<hashes::keccak_1600<512>>(a);

    BOOST_CHECK_EQUAL(
        "cccc49fa63822b00004cf6c889b28a035440ffb3ef50e790599935518e2aefb0"
        "e2f1839170797f7763a5c43b2dcf02abf579950e36358d6d04dfddc2abac7545",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(keccak_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(keccak_224_accumulator, fixture<224>) {
    // "abc"
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(keccak_256_accumulator, fixture<256>) {
    // "abc"
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(keccak_384_accumulator, fixture<384>) {
    // "abc"
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
        "f8c681e4afaf31a34db29fb763e3c28e",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(keccak_512_accumulator, fixture<512>) {
    // "abc"
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
        "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(keccak_preprocessor_test_suite)

BOOST_AUTO_TEST_CASE(keccak_224_preprocessor1) {
    accumulator_set<hashes::keccak_1600<224>> acc;
    hashes::keccak_1600<224>::digest_type s = extract::hash<hashes::keccak_1600<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_224_preprocessor2) {
    accumulator_set<hashes::keccak_1600<224>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::keccak_1600<224>::digest_type s = extract::hash<hashes::keccak_1600<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_256_preprocessor1) {
    accumulator_set<hashes::keccak_1600<256>> acc;
    hashes::keccak_1600<256>::digest_type s = extract::hash<hashes::keccak_1600<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_256_preprocessor2) {
    accumulator_set<hashes::keccak_1600<256>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::keccak_1600<256>::digest_type s = extract::hash<hashes::keccak_1600<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_384_preprocessor1) {
    accumulator_set<hashes::keccak_1600<384>> acc;
    hashes::keccak_1600<384>::digest_type s = extract::hash<hashes::keccak_1600<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b"
        "2dd2b21362337441ac12b515911957ff",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_384_preprocessor2) {
    accumulator_set<hashes::keccak_1600<384>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::keccak_1600<384>::digest_type s = extract::hash<hashes::keccak_1600<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99"
        "f8c681e4afaf31a34db29fb763e3c28e",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_512_preprocessor1) {
    accumulator_set<hashes::keccak_1600<512>> acc;
    hashes::keccak_1600<512>::digest_type s = extract::hash<hashes::keccak_1600<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
        "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(keccak_512_preprocessor2) {
    accumulator_set<hashes::keccak_1600<512>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::keccak_1600<512>::digest_type s = extract::hash<hashes::keccak_1600<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
        "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()

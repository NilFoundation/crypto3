//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin
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

#define BOOST_TEST_MODULE blake2b_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::blake2b<224>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::blake2b<256>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::blake2b<384>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::blake2b<512>::construction::type::digest_type)

template<std::size_t Size>
class fixture {
public:
    accumulator_set<hashes::blake2b<Size>> acc;
    typedef hashes::blake2b<Size> hash_t;
    virtual ~fixture() {
    }
};

const char *test_data = "data/blake2b.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(blake2b_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(blake2b_224_string_various_range_value_hash, string_data("data_224"), array_element) {
    std::string out = hash<hashes::blake2b<224>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_224_string_various_itr_value_hash, string_data("data_224"), array_element) {
    std::string out = hash<hashes::blake2b<224>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_256_string_various_range_value_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::blake2b<256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_256_string_various_itr_value_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::blake2b<256>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_384_string_various_range_value_hash, string_data("data_384"), array_element) {
    std::string out = hash<hashes::blake2b<384>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_384_string_various_itr_value_hash, string_data("data_384"), array_element) {
    std::string out = hash<hashes::blake2b<384>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_512_string_various_range_value_hash, string_data("data_512"), array_element) {
    std::string out = hash<hashes::blake2b<512>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_512_string_various_itr_value_hash, string_data("data_512"), array_element) {
    std::string out = hash<hashes::blake2b<512>>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blake2b_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(blake2b_224_string_various_range_value_hash, string_data("data_224"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::blake2b<224>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_256_string_various_range_value_hash, string_data("data_256"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::blake2b<256>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_384_string_various_range_value_hash, string_data("data_384"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::blake2b<384>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(blake2b_512_string_various_range_value_hash, string_data("data_512"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::blake2b<512>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blake2b_stream_processor_test_suite)

BOOST_AUTO_TEST_CASE(blake2b_224_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::blake2b<224>::digest_type d = hash<hashes::blake2b<224>>(a);

    BOOST_CHECK_EQUAL("c05d5ea0257c7a4604122b8e99a0093f89d0797ef06a7f0af65a3560", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_224_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::blake2b<224>::digest_type d = hash<hashes::blake2b<224>>(a);

    BOOST_CHECK_EQUAL("9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_224_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::blake2b<224>::digest_type d = hash<hashes::blake2b<224>>(a);

    BOOST_CHECK_EQUAL("f305a410b733771b7c5c8ad1041e356ff1da48c51792dfe319ba286b", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_256_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::blake2b<256>::digest_type d = hash<hashes::blake2b<256>>(a);

    BOOST_CHECK_EQUAL("8928aae63c84d87ea098564d1e03ad813f107add474e56aedd286349c0c03ea4", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_256_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::blake2b<256>::digest_type d = hash<hashes::blake2b<256>>(a);

    BOOST_CHECK_EQUAL("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_256_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::blake2b<256>::digest_type d = hash<hashes::blake2b<256>>(a);

    BOOST_CHECK_EQUAL("31a65b562925c6ffefdafa0ad830f4e33eff148856c2b4754de273814adf8b85", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_384_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::blake2b<384>::digest_type d = hash<hashes::blake2b<384>>(a);

    BOOST_CHECK_EQUAL(
        "7d40de16ff771d4595bf70cbda0c4ea0a066a6046fa73d34471cd4d93d827d7c"
        "94c29399c50de86983af1ec61d5dcef0",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_384_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::blake2b<384>::digest_type d = hash<hashes::blake2b<384>>(a);

    BOOST_CHECK_EQUAL(
        "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
        "c66ba83be64b302d7cba6ce15bb556f4",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_384_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::blake2b<384>::digest_type d = hash<hashes::blake2b<384>>(a);

    BOOST_CHECK_EQUAL(
        "44c3965bd8f02ed299ad52ffb5bba7c448df242073c5520dc091a0cc55d024cd"
        "d51569c339d0bf2b6cd746708683a0ef",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_512_shortmsg_byte1) {
    // "a"
    std::array<char, 1> a = {'\x61'};
    hashes::blake2b<512>::digest_type d = hash<hashes::blake2b<512>>(a);

    BOOST_CHECK_EQUAL(
        "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34"
        "d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_512_shortmsg_byte2) {
    // "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::blake2b<512>::digest_type d = hash<hashes::blake2b<512>>(a);

    BOOST_CHECK_EQUAL(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_512_shortmsg_byte3) {
    // "message digest"
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::blake2b<512>::digest_type d = hash<hashes::blake2b<512>>(a);

    BOOST_CHECK_EQUAL(
        "3c26ce487b1c0f062363afa3c675ebdbf5f4ef9bdc022cfbef91e3111cdc2838"
        "40d8331fc30a8a0906cff4bcdbcd230c61aaec60fdfad457ed96b709a382359a",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(blake2b_longmsg_byte1) {
    std::array<char, 113> a = {
        '\xBE', '\xFA', '\xB5', '\x74', '\x39', '\x6D', '\x7F', '\x8B', '\x67', '\x05', '\xE2', '\xD5', '\xB5',
        '\x8B', '\x2C', '\x1C', '\x82', '\x0B', '\xB2', '\x4E', '\x3F', '\x4B', '\xAE', '\x3E', '\x8F', '\xBC',
        '\xD3', '\x6D', '\xBF', '\x73', '\x4E', '\xE1', '\x4E', '\x5D', '\x6A', '\xB9', '\x72', '\xAE', '\xDD',
        '\x35', '\x40', '\x23', '\x54', '\x66', '\xE8', '\x25', '\x85', '\x0E', '\xE4', '\xC5', '\x12', '\xEA',
        '\x97', '\x95', '\xAB', '\xFD', '\x33', '\xF3', '\x30', '\xD9', '\xFD', '\x7F', '\x79', '\xE6', '\x2B',
        '\xBB', '\x63', '\xA6', '\xEA', '\x85', '\xDE', '\x15', '\xBE', '\xAE', '\xEA', '\x6F', '\x8D', '\x20',
        '\x4A', '\x28', '\x95', '\x60', '\x59', '\xE2', '\x63', '\x2D', '\x11', '\x86', '\x1D', '\xFB', '\x0E',
        '\x65', '\xBC', '\x07', '\xAC', '\x8A', '\x15', '\x93', '\x88', '\xD5', '\xC3', '\x27', '\x7E', '\x22',
        '\x72', '\x86', '\xF6', '\x5F', '\xF5', '\xE5', '\xB5', '\xAE', '\xC1'};
    hashes::blake2b<224>::digest_type d = hash<hashes::blake2b<224>>(a);

    BOOST_CHECK_EQUAL("3d6c866ebaa149e0c6ad8ba5e9a685e1ad56d81a00fb99d9020f11c0", std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blake2b_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(blake2b_224_accumulator1, fixture<224>) {
    // "a"
    hashes::blake2b<224>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000000061);
    acc(m, accumulators::bits = 8);
    hashes::blake2b<224>::digest_type s = extract::hash<hashes::blake2b<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("c05d5ea0257c7a4604122b8e99a0093f89d0797ef06a7f0af65a3560", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_224_accumulator2, fixture<224>) {
    // "abc"
    hashes::blake2b<224>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000636261);
    acc(m, accumulators::bits = 24);
    hashes::blake2b<224>::digest_type s = extract::hash<hashes::blake2b<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_256_accumulator1, fixture<256>) {
    // "a"
    hashes::blake2b<256>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000000061);
    acc(m, accumulators::bits = 8);
    hashes::blake2b<256>::digest_type s = extract::hash<hashes::blake2b<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("8928aae63c84d87ea098564d1e03ad813f107add474e56aedd286349c0c03ea4", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_256_accumulator2, fixture<256>) {
    // "abc"
    hashes::blake2b<256>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000636261);
    acc(m, accumulators::bits = 24);
    hashes::blake2b<256>::digest_type s = extract::hash<hashes::blake2b<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_384_accumulator1, fixture<384>) {
    // "a"
    hashes::blake2b<384>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000000061);
    acc(m, accumulators::bits = 8);
    hashes::blake2b<384>::digest_type s = extract::hash<hashes::blake2b<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL(
        "7d40de16ff771d4595bf70cbda0c4ea0a066a6046fa73d34471cd4d93d827d7c"
        "94c29399c50de86983af1ec61d5dcef0",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_384_accumulator2, fixture<384>) {
    // "abc"
    hashes::blake2b<384>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000636261);
    acc(m, accumulators::bits = 24);
    hashes::blake2b<384>::digest_type s = extract::hash<hashes::blake2b<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL(
        "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
        "c66ba83be64b302d7cba6ce15bb556f4",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_512_accumulator1, fixture<512>) {
    // "a"
    hashes::blake2b<512>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000000061);
    acc(m, accumulators::bits = 8);
    hashes::blake2b<512>::digest_type s = extract::hash<hashes::blake2b<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL(
        "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34"
        "d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(blake2b_512_accumulator2, fixture<512>) {
    // "abc"
    hashes::blake2b<512>::block_type m = {{}};
    m[0] = UINT64_C(0x0000000000636261);
    acc(m, accumulators::bits = 24);
    hashes::blake2b<512>::digest_type s = extract::hash<hashes::blake2b<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s));
#endif

    BOOST_CHECK_EQUAL(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_224_preprocessor1) {
    accumulator_set<hashes::blake2b<224>> acc;
    hashes::blake2b<224>::digest_type s = extract::hash<hashes::blake2b<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_224_preprocessor2) {
    accumulator_set<hashes::blake2b<224>> acc;

    acc(UINT64_C(0x0000000000000061), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000062), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000063), accumulators::bits = 8);

    hashes::blake2b<224>::digest_type s = extract::hash<hashes::blake2b<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_256_preprocessor1) {
    accumulator_set<hashes::blake2b<256>> acc;
    hashes::blake2b<256>::digest_type s = extract::hash<hashes::blake2b<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_256_preprocessor2) {
    accumulator_set<hashes::blake2b<256>> acc;

    acc(UINT64_C(0x0000000000000061), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000062), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000063), accumulators::bits = 8);

    hashes::blake2b<256>::digest_type s = extract::hash<hashes::blake2b<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_384_preprocessor1) {
    accumulator_set<hashes::blake2b<384>> acc;
    hashes::blake2b<384>::digest_type s = extract::hash<hashes::blake2b<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd324"
        "4a6caf0498812673c5e05ef583825100",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_384_preprocessor2) {
    accumulator_set<hashes::blake2b<384>> acc;

    acc(UINT64_C(0x0000000000000061), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000062), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000063), accumulators::bits = 8);

    hashes::blake2b<384>::digest_type s = extract::hash<hashes::blake2b<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
        "c66ba83be64b302d7cba6ce15bb556f4",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_512_preprocessor1) {
    accumulator_set<hashes::blake2b<512>> acc;
    hashes::blake2b<512>::digest_type s = extract::hash<hashes::blake2b<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(blake2b_512_preprocessor2) {
    accumulator_set<hashes::blake2b<512>> acc;

    acc(UINT64_C(0x0000000000000061), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000062), accumulators::bits = 8);
    acc(UINT64_C(0x0000000000000063), accumulators::bits = 8);

    hashes::blake2b<512>::digest_type s = extract::hash<hashes::blake2b<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()

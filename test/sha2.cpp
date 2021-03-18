//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE sha2_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/sha2.hpp>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha2<224>::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha2<256>::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha2<384>::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha2<512>::digest_type)

template<std::size_t Size>
class fixture {
public:
    accumulator_set<hashes::sha2<Size>> acc;
    typedef hashes::sha2<Size> hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/sha2.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(sha2_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(sha2_224_range_hash, string_data("data_224"), array_element) {
    std::string out = hash<hashes::sha2<224>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha2_256_range_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::sha2<256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha2_384_range_hash, string_data("data_384"), array_element) {
    hashes::sha2<384>::digest_type out = hash<hashes::sha2<384>>(array_element.first);

    BOOST_CHECK_EQUAL(std::to_string(out).data(), array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha2_512_range_hash, string_data("data_512"), array_element) {
    std::string out = hash<hashes::sha2<512>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha2_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(sha2_224_range_hash, string_data("data_224"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::sha2<224>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha2_256_range_hash, string_data("data_256"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::sha2<256>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha2_384_range_hash, string_data("data_384"), array_element) {
    hashes::sha2<384>::digest_type out = array_element.first | adaptors::hashed<hashes::sha2<384>>;

    BOOST_CHECK_EQUAL(std::to_string(out).data(), array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha2_512_range_hash, string_data("data_512"), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::sha2<512>>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha2_stream_processor_test_suite)

//
// Appendix references are from
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
//

//
// Additional test vectors from
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
//

BOOST_AUTO_TEST_CASE(sha2_224_shortmsg_bit) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf
    //      https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    // B.1/1
    std::array<bool, 5> a = {0, 1, 1, 0, 1};
    hashes::sha2<224>::digest_type d = hash<hashes::sha2<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("e3b048552c3c387bcab37f6eb06bb79b96a4aee5ff27f51531a9551c", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_224_shortmsg_bit1) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

    // B.1/1
    std::array<bool, 10> a = {0, 1, 0, 1, 0, 0, 0, 0, 0, 1};
    hashes::sha2<224>::digest_type d = hash<hashes::sha2<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("869944dc261b4affdcd429d00f0bc5c43f2fe545bef20a77980098cd", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_224_shortmsg_bit2) {
    // C.1/1
    std::array<bool, 5> a = {0, 1, 1, 0, 1};
    hashes::sha2<256>::digest_type d = hash<hashes::sha2<256>>(a);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL("d6d3e02a31a84a8caa9718ed6c2057be09db45e7823eb5079ce7a573a3760f95", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_224_shortmsg_byte) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf
    //      https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    // B.1/1
    std::array<char, 1> a = {'\x84'};
    hashes::sha2<224>::digest_type d = hash<hashes::sha2<224>>(a);

    BOOST_CHECK_EQUAL("3cd36921df5d6963e73739cf4d20211e2d8877c19cff087ade9d0e3a", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_224_shortmsg_byte1) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf
    //      https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    // B.1/1
    std::array<char, 10> a = {'\x00', '\x64', '\x70', '\xd5', '\x7d', '\xad', '\x98', '\x93', '\xdc', '\x03'};
    hashes::sha2<224>::digest_type d = hash<hashes::sha2<224>>(a);

    BOOST_CHECK_EQUAL("c90026cda5ad24115059c62ae9add57793ade445d4742273288bbce7", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_256_shortmsg_byte) {
    // From https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    std::array<char, 7> a = {'\x06', '\xe0', '\x76', '\xf5', '\xa4', '\x42', '\xd5'};
    hashes::sha2<256>::digest_type d = hash<hashes::sha2<256>>(a);

    BOOST_CHECK_EQUAL("3fd877e27450e6bbd5d74bb82f9870c64c66e109418baa8e6bbcff355e287926", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_256_shortmsg_byte1) {
    // From https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    std::array<char, 22> a = {'\xea', '\x15', '\x7c', '\x02', '\xeb', '\xaf', '\x1b', '\x22', '\xde', '\x22', '\x1b',
                              '\x53', '\xf2', '\x35', '\x39', '\x36', '\xd2', '\x35', '\x9d', '\x1e', '\x1c', '\x97'};
    hashes::sha2<256>::digest_type d = hash<hashes::sha2<256>>(a);

    BOOST_CHECK_EQUAL("9df5c16a3f580406f07d96149303d8c408869b32053b726cf3defd241e484957", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_384_shortmsg_bit) {
    // D.1/1
    std::array<bool, 5> a = {0, 0, 0, 1, 0};
    hashes::sha2<384>::digest_type d = hash<hashes::sha2<384>>(a);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL(
        "8d17be79e32b6718e07d8a603eb84ba0478f7fcfd1bb93995f7d1149e09143ac1ffcfc56820e469f3878d957a15a3fe4",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_384_shortmsg_byte) {
    // From https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    std::array<char, 2> a = {'\x6e', '\xce'};
    hashes::sha2<384>::digest_type d = hash<hashes::sha2<384>>(a);

    BOOST_CHECK_EQUAL(
        "53d4773da50d8be4145d8f3a7098ff3691a554a29ae6f652cc7121eb8bc96fd2210e06ae2fa2a36c4b3b3497341e70f0",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_384_shortmsg_byte2) {
    // From https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    std::array<char, 12> a = {'\x22', '\x09', '\x11', '\x2e', '\xe7', '\x79',
                              '\xbf', '\x6d', '\x95', '\x71', '\x11', '\x05'};
    hashes::sha2<384>::digest_type d = hash<hashes::sha2<384>>(a);

    BOOST_CHECK_EQUAL(
        "09c54bf533a26c7447caa5783db2ec7ef5e55752da7f2a2c4e360982a94ec1ca2cb6a157d34eed28de978b4145e17ebc",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_512_shortmsg_bit) {
    // E.1/1
    std::array<bool, 5> a = {1, 0, 1, 1, 0};
    hashes::sha2<512>::digest_type d = hash<hashes::sha2<512>>(a);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL(
        "d4ee29a9e90985446b913cf1d1376c836f4be2c1cf3cada0720a6bf4857d886a7ecb3c4e4c0fa8c7f95214e41dc1b0d21b22a84cc03bf8"
        "ce4845f34dd5bdbad4",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_512_shortmsg_byte) {
    // From https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    std::array<char, 5> a = {'\xeb', '\x0c', '\xa9', '\x46', '\xc1'};
    hashes::sha2<512>::digest_type d = hash<hashes::sha2<512>>(a);

    BOOST_CHECK_EQUAL(
        "d39ecedfe6e705a821aee4f58bfc489c3d9433eb4ac1b03a97e321a2586b40dd0522f40fa5aef36afff591a78c916bfc6d1ca515c4983d"
        "d8695b1ec7951d723e",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_512_shortmsg_byte2) {
    // From https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    std::array<char, 20> a = {'\xe0', '\x70', '\x56', '\xd4', '\xf7', '\x27', '\x7b', '\xc5', '\x48', '\x09',
                              '\x95', '\x77', '\x72', '\x0a', '\x58', '\x1e', '\xec', '\x94', '\x14', '\x1d'};
    hashes::sha2<512>::digest_type d = hash<hashes::sha2<512>>(a);

    BOOST_CHECK_EQUAL(
        "59f1856303ff165e2ab5683dddeb6e8ad81f15bb578579b999eb5746680f22cfec6dba741e591ca4d9e53904837701b374be74bbc0847a"
        "92179ac2b67496d807",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha2_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator2, fixture<256>) {
    // Example from appendix B.1: echo -n "abc" | sha256sum
    hash_t::construction::type::block_type m = {{}};
    m[0] = 0x61626300;
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator3, fixture<256>) {
    // Example from appendix B.2:
    // echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha256sum
    hash_t::construction::type::block_type m1 = {
        {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x61010101, 0x01010101, 0x80000000, 0x00000000}};
    acc(m1, accumulators::bits = (512 - 64 - 64 + 8));

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL("1afbf54773a9a85be9ba0b691b6b21560772969e1bec2dd3cd77a56f39ba61bf", std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {0x6d6e6f70, 0x6e6f7071, 0x6d6e6f70, 0x6e6f7071, 0x6d6e6f70, 0x6e6f7071, 0x0168696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d010170, 0x6e6f7071, 0x80080000, 0x00000000}};

    acc(m2, accumulators::bits = 64 + 64 + 64);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("26eba60be9d10a6484d03392b011d481b33e9b0038175942876ced989c68cab1", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_384_accumulator2, fixture<384>) {
    // Example from appendix D.1: echo -n "abc" | sha384sum
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x6162630000000000);

    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_384_accumulator3, fixture<384>) {
    // Example from appendix D.2:
    // echo -n "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn (continues)
    //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" | sha384sum
    hash_t::construction::type::block_type m1 = {
        {UINT64_C(0x6162636465666768), UINT64_C(0x6263646566676869), UINT64_C(0x636465666768696a),
         UINT64_C(0x6465666768696a6b), UINT64_C(0x65666768696a6b6c), UINT64_C(0x666768696a6b6c6d),
         UINT64_C(0x6768696a6b6c6d6e), UINT64_C(0x68696a6b6c6d6e6f), UINT64_C(0x696a6b6c6d6e6f70),
         UINT64_C(0x6a6b6c6d6e6f7071), UINT64_C(0x6b6c6d6e6f707172), UINT64_C(0x6c6d6e6f70717273),
         UINT64_C(0x6d6e6f7071727374), UINT64_C(0x6e6f707172737475), UINT64_C(0x0000000000000000),
         UINT64_C(0x0000000000000000)}};
    acc(m1, accumulators::bits = 1024 - 128);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
        "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_512_accumulator2, fixture<512>) {
    // Example from appendix C.1: echo -n "abc" | sha512sum
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_512_accumulator3, fixture<512>) {
    // Example from appendix C.2:
    // echo -n "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn (continues)
    //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" | sha512sum
    hash_t::construction::type::block_type m1 = {{
        UINT64_C(0x6162636465666768),
        UINT64_C(0x6263646566676869),
        UINT64_C(0x636465666768696a),
        UINT64_C(0x6465666768696a6b),
        UINT64_C(0x65666768696a6b6c),
        UINT64_C(0x666768696a6b6c6d),
        UINT64_C(0x6768696a6b6c6d6e),
        UINT64_C(0x68696a6b6c6d6e6f),
        UINT64_C(0x696a6b6c6d6e6f70),
        UINT64_C(0x6a6b6c6d6e6f7071),
        UINT64_C(0x6b6c6d6e6f707172),
        UINT64_C(0x6c6d6e6f70717273),
        UINT64_C(0x6d6e6f7071727374),
        UINT64_C(0x6e6f707172737475),
        UINT64_C(0x0000000000000000),
        UINT64_C(0x0000000000000000),
    }};
    acc(m1, accumulators::bits = 1024 - 128);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor1) {
    accumulator_set<hashes::sha2<256>> acc;
    hashes::sha2<256>::digest_type s = extract::hash<hashes::sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor2) {
    // Example from Appendix B.1
    accumulator_set<hashes::sha2<256>> acc;
    acc(0x61000000, accumulators::bits = 8);
    acc(0x62000000, accumulators::bits = 8);
    acc(0x63000000, accumulators::bits = 8);

    hashes::sha2<256>::digest_type s = extract::hash<hashes::sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor3) {

    // Example from Appendix B.3
    accumulator_set<hashes::sha2<256>> acc;
    for (unsigned i = 0; i < 62; ++i) {
        acc(0x61000000, accumulators::bits = 8);
    }
    hashes::sha2<256>::digest_type s = extract::hash<hashes::sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("f506898cc7c2e092f9eb9fadae7ba50383f5b46a2a4fe5597dbb553a78981268", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor4) {

    // Example from Appendix B.3
    accumulator_set<hashes::sha2<256>> acc;

    hashes::sha2<256>::construction::type::block_type m1 = {
        {0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
         0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61610101}};

    acc(m1, accumulators::bits = 62 * 8);
    // for (unsigned i = 0; i < 63; ++i) {
    acc(0x61000000, accumulators::bits = 8);
    //}
    hashes::sha2<256>::digest_type s = extract::hash<hashes::sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor5) {

    // Example from Appendix B.3
    accumulator_set<hashes::sha2<256>> acc;

    hashes::sha2<256>::construction::type::block_type m1 = {
        {0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161,
         0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616101}};

    acc(m1, accumulators::bits = 63 * 8);
    // for (unsigned i = 0; i < 63; ++i) {
    // acc(0x61000000, accumulators::bits = 8);
    //}
    hashes::sha2<256>::digest_type s = extract::hash<hashes::sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor6) {

    // Example from Appendix B.3
    accumulator_set<hashes::sha2<256>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc(0x61000000, accumulators::bits = 8);
    }
    hashes::sha2<256>::digest_type s = extract::hash<hashes::sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha384_preprocessor1) {
    accumulator_set<hashes::sha2<384>> acc;
    hashes::sha2<384>::digest_type s = extract::hash<hashes::sha2<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
        "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha384_preprocessor2) {
    // Example from Appendix D.1
    accumulator_set<hashes::sha2<384>> acc;
    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);
    hashes::sha2<384>::digest_type s = extract::hash<hashes::sha2<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha384_preprocessor3) {
    // Example from Appendix D.1
    // Example from Appendix D.3
    accumulator_set<hashes::sha2<384>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    }
    hashes::sha2<384>::digest_type s = extract::hash<hashes::sha2<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
        "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha512_preprocessor1) {
    accumulator_set<hashes::sha2<512>> acc;
    hashes::sha2<512>::digest_type s = extract::hash<hashes::sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha512_preprocessor2) {
    // Example from Appendix C.1
    accumulator_set<hashes::sha2<512>> acc;
    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::sha2<512>::digest_type s = extract::hash<hashes::sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha512_preprocessor3) {
    // Example from Appendix C.3
    accumulator_set<hashes::sha2<512>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    }
    hashes::sha2<512>::digest_type s = extract::hash<hashes::sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha224_range_hash) {
    hashes::sha2<224>::digest_type h = hash<hashes::sha2<224>>(std::string("abc"));
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif
    BOOST_CHECK_EQUAL("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", std::to_string(h).data());
}

BOOST_AUTO_TEST_SUITE_END()
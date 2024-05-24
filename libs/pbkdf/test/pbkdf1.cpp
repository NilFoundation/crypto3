//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE pbkdf_test

//#define CRYPTO3_HASH_SHOW_PROGRESS
#include <nil/crypto3/pbkdf/algorithm/derive.hpp>

#include <nil/crypto3/pbkdf/pbkdf1.hpp>

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

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

BOOST_TEST_DONT_PRINT_LOG_VALUE(bcrypt<128>::construction_type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(bcrypt<160>::construction_type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(bcrypt<256>::construction_type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(bcrypt<320>::construction_type::digest_type)

static const std::unordered_map<std::string, std::string> string_128_data = {
    {"", "cdf26213a150dc3ecb610f18f6b38b46"},
    {"a", "86be7afa339d0fc7cfc785e72f578d33"},
    {"abc", "c14a12199c66e4ba84636b0f69144c77"},
    {"message digest", "9e327b3d6e523062afc1132d7df9d1b8"},
    {"abcdefghijklmnopqrstuvwxyz", "fd2aa607f71dc8f510714922b371834e"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "a1aa0689d0fafa2ddc22e88b49133a06"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d1e959eb179c911faea4624c60c5c702"}};

static const std::unordered_map<std::string, std::string> string_160_data = {
    {"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
    {"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
    {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
    {"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
    {"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"}};

static const std::unordered_map<std::string, std::string> string_256_data = {
    {"", "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"},
    {"a", "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925"},
    {"abc", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"},
    {"message digest", "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e"},
    {"abcdefghijklmnopqrstuvwxyz", "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8"}};

static const std::unordered_map<std::string, std::string> string_320_data = {
    {"", "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"},
    {"a", "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d"},
    {"abc", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d"},
    {"message digest", "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197"},
    {"abcdefghijklmnopqrstuvwxyz", "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4"}};

BOOST_AUTO_TEST_SUITE(pbkdf_test_suite)

BOOST_DATA_TEST_CASE(pbkdf_128_range_hash, boost::unit_test::data::make(string_128_data), array_element) {
    std::string out = hash<bcrypt<128>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_160_range_hash, boost::unit_test::data::make(string_160_data), array_element) {
    std::string out = hash<bcrypt<160>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_256_range_hash, boost::unit_test::data::make(string_256_data), array_element) {
    std::string out = hash<bcrypt<256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_320_range_hash, boost::unit_test::data::make(string_320_data), array_element) {
    std::string out = hash<bcrypt<320>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_128_typedef_range_hash, boost::unit_test::data::make(string_128_data), array_element) {
    std::string out = hash<bcrypt128>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_160_typedef_range_hash, boost::unit_test::data::make(string_160_data), array_element) {
    std::string out = hash<bcrypt160>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_256_typedef_range_hash, boost::unit_test::data::make(string_256_data), array_element) {
    std::string out = hash<bcrypt256>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(pbkdf_320_typedef_range_hash, boost::unit_test::data::make(string_320_data), array_element) {
    std::string out = hash<bcrypt320>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_SUITE_END()
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

#define BOOST_TEST_MODULE salsa20_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/stream/algorithm/encrypt.hpp>
#include <nil/crypto3/stream/algorithm/decrypt.hpp>
#include <nil/crypto3/stream/algorithm/seek.hpp>

#include <nil/crypto3/stream/salsa20.hpp>

using namespace nil::crypto3::stream;

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
typedef std::unordered_map <std::string, std::string> string_data;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

typedef std::unordered_map<std::string, std::vector < uint8_t>>
::value_type byte_vector_data_value;
typedef std::unordered_map <std::string, std::vector<uint8_t>> byte_vector_data;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_data_value)

typedef std::vector <uint8_t> byte_vector_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_t)

typedef std::vector <std::string> string_vector_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_vector_t)

static const byte_vector_data valid_data = {{"Zg==",                                     {0x66}},
                                            {"Zm8=",                                     {0x66, 0x6F}},
                                            {"Zm9v",                                     {0x66, 0x6F, 0x6F}},
                                            {"aGVsbG8gd29ybGQ=",                         {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64}},
                                            {"aGVsbG8gd29ybGQh",                         {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21}},
                                            {"SGVsbG8sIHdvcmxkLg==",                     {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2E}},
                                            {"VGhlIDEyIGNoYXJz",                         {0x54, 0x68, 0x65, 0x20, 0x31, 0x32, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73}},
                                            {"VGhlIDEzIGNoYXJzLg==",                     {0x54, 0x68, 0x65, 0x20, 0x31, 0x33, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E}},
                                            {"VGhlIDE0IGNoYXJzLi4=",                     {0x54, 0x68, 0x65, 0x20, 0x31, 0x34, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E, 0x2E}},
                                            {"VGhlIDE1IGNoYXJzLi4u",                     {0x54, 0x68, 0x65, 0x20, 0x31, 0x35, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E, 0x2E, 0x2E}},
                                            {"QW4gVVRGLTggdXVtbDogw7w=",                 {0x41, 0x6E, 0x20, 0x55, 0x54, 0x46, 0x2D, 0x38, 0x20, 0x75, 0x75, 0x6D, 0x6C, 0x3A, 0x20, 0xC3, 0xBC}},
                                            {"V2VpcmQgR2VybWFuIDIgYnl0ZSB0aGluZzogw58u", {0x57, 0x65, 0x69, 0x72, 0x64, 0x20, 0x47, 0x65, 0x72, 0x6D, 0x61, 0x6E, 0x20, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x20, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0xC3, 0x9F, 0x2E}},
                                            {"mw==",                                     {0x9B}},
                                            {"HGA=",                                     {0x1C, 0x60}},
                                            {"gTS9",                                     {0x81, 0x34, 0xBD}},
                                            {"Xmz/3g==",                                 {0x5E, 0x6C, 0xFF, 0xDE}},
                                            {"ss3w3H8=",                                 {0xb2, 0xcd, 0xf0, 0xdc, 0x7f}},
                                            {"/FYt2tQO",                                 {0xfc, 0x56, 0x2d, 0xda, 0xd4, 0x0e}},
                                            {"KbIyLohB6A==",                             {0x29, 0xb2, 0x32, 0x2e, 0x88, 0x41, 0xe8}},
                                            {"Dw/O2Ul6r5I=",                             {0x0f, 0x0f, 0xce, 0xd9, 0x49, 0x7a, 0xaf, 0x92}},
                                            {"Jw+xiYKADaZA",                             {0x27, 0x0f, 0xb1, 0x89, 0x82, 0x80, 0x0d, 0xa6, 0x40}}};

static const string_vector_t invalid_data = {"ZOOL!isnotvalidbase64", "Neitheris:this?"};

BOOST_AUTO_TEST_SUITE(salsa20_test_suite)

BOOST_DATA_TEST_CASE(salsa20_single_range_encrypt, boost::unit_test::data::random(0, 16)
^ boost::unit_test::data::xrange(7), random_sample, index) {

}

BOOST_AUTO_TEST_SUITE_END()
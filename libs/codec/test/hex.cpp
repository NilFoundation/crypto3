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

#define BOOST_TEST_MODULE hex_encoding_test

#include <string>
#include <vector>
#include <array>
#include <iterator>
#include <algorithm>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>

#include <nil/crypto3/codec/adaptor/coded.hpp>

#include <nil/crypto3/codec/hex.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::codec;

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
}

const char *test_data = "data/hex.json";

boost::property_tree::ptree mode_data(const char *mode) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);

    return root_data.get_child(mode);
}

BOOST_AUTO_TEST_SUITE(hex_codec_algorithm_test_suite)

BOOST_DATA_TEST_CASE(hex_upper_range_range_encode, mode_data("upper_mode"), array_element) {
    std::string result = encode<hex<mode::upper>>(array_element.first);
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_upper_range_range_decode, mode_data("upper_mode"), array_element) {
    std::string result = decode<hex<mode::upper>>(array_element.second.data());
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_range_encode, mode_data("upper_mode"), array_element) {
    std::string result = encode<hex<mode::upper>>(array_element.first.begin(), array_element.first.end());
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_range_decode, mode_data("upper_mode"), array_element) {
    std::string result = decode<hex<mode::upper>>(array_element.second.data().begin(), array_element.second.data().end());
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_upper_range_iterator_encode, mode_data("upper_mode"), array_element) {
    std::string result;
    encode<hex<mode::upper>>(array_element.first, std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_upper_range_iterator_decode, mode_data("upper_mode"), array_element) {
    std::string result;
    decode<hex<mode::upper>>(array_element.second.data(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_iterator_encode, mode_data("upper_mode"), array_element) {
    std::string result;
    encode<hex<mode::upper>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_iterator_decode, mode_data("upper_mode"), array_element) {
    std::string result;
    decode<hex<mode::upper>>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_range_range_encode, mode_data("lower_mode"), array_element) {
    std::string result = encode<hex<mode::lower>>(array_element.first);
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_lower_range_range_decode, mode_data("lower_mode"), array_element) {
    std::string result = decode<hex<mode::lower>>(array_element.second.data());
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_range_encode, mode_data("lower_mode"), array_element) {
    std::string result = encode<hex<mode::lower>>(array_element.first.begin(), array_element.first.end());
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_range_decode, mode_data("lower_mode"), array_element) {
    std::string result = decode<hex<mode::lower>>(array_element.second.data().begin(), array_element.second.data().end());
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_range_iterator_encode, mode_data("lower_mode"), array_element) {
    std::string result;
    encode<hex<mode::lower>>(array_element.first, std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_lower_range_iterator_decode, mode_data("lower_mode"), array_element) {
    std::string result;
    decode<hex<mode::lower>>(array_element.second.data(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_iterator_encode, mode_data("lower_mode"), array_element) {
    std::string result;
    encode<hex<mode::lower>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second.data());
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_iterator_decode, mode_data("lower_mode"), array_element) {
    std::string result;
    decode<hex<mode::lower>>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_AUTO_TEST_SUITE_END()


template<std::size_t Size, typename Integer>
static inline typename boost::uint_t<Size>::exact extract_uint_t(Integer v, std::size_t position) {
    return static_cast<typename boost::uint_t<Size>::exact>(v >> (((~position) & (sizeof(Integer) - 1)) << 3));
}

template<typename Integer>
std::array<std::uint8_t, sizeof(Integer)> to_byte_array(Integer i) {
    std::array<std::uint8_t, sizeof(Integer)> res;
    for (int itr = 0; itr < sizeof(Integer); itr++) {
        res[itr] = extract_uint_t<CHAR_BIT>(i, itr);
    }
    return res;
}

BOOST_AUTO_TEST_SUITE(hex_codec_random_data_test_suite)

BOOST_DATA_TEST_CASE(hex_upper_single_range_random_encode_decode,
                     boost::unit_test::data::random(std::numeric_limits<std::uintmax_t>::min(),
                                                    std::numeric_limits<std::uintmax_t>::max()) ^
                         boost::unit_test::data::xrange(std::numeric_limits<std::uint8_t>::max()),
                     random_sample, index) {
    std::array<std::uint8_t, sizeof(decltype(random_sample))> arr = to_byte_array(random_sample);
    arr[arr.size() - 1] = std::max((std::uint8_t)1, arr[arr.size() - 1]);    // Compliant with RFC 4648
    std::vector<std::uint8_t> enc = encode<hex<mode::upper>>(arr);
    std::vector<std::uint8_t> out = decode<hex<mode::upper>>(enc);
    BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(), arr.begin(), arr.end());
}

BOOST_DATA_TEST_CASE(hex_lower_single_range_random_encode_decode,
                     boost::unit_test::data::random(std::numeric_limits<std::uintmax_t>::min(),
                                                    std::numeric_limits<std::uintmax_t>::max()) ^
                         boost::unit_test::data::xrange(std::numeric_limits<std::uint8_t>::max()),
                     random_sample, index) {
    std::array<std::uint8_t, sizeof(decltype(random_sample))> arr = to_byte_array(random_sample);
    arr[arr.size() - 1] = std::max((std::uint8_t)1, arr[arr.size() - 1]);    // Compliant with RFC 4648
    std::vector<std::uint8_t> enc = encode<hex<mode::lower>>(arr);
    std::vector<std::uint8_t> out = decode<hex<mode::lower>>(enc);
    BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(), arr.begin(), arr.end());
}

BOOST_AUTO_TEST_SUITE_END()

//BOOST_AUTO_TEST_SUITE(hex_codec_adaptor_test_suite)
//
//    BOOST_DATA_TEST_CASE(hex_upper_range_encode, mode_data("upper_mode"), array_element) {
//        BOOST_CHECK((array_element.first | adaptors::encoded<codec::hex<>>) == array_element.second);
//    }
//
//    BOOST_DATA_TEST_CASE(hex_upper_range_decode, mode_data("upper_mode"), array_element) {
//        BOOST_CHECK((array_element.second | adaptors::decoded<codec::hex<>>) == array_element.first);
//    }
//
//BOOST_AUTO_TEST_SUITE_END()

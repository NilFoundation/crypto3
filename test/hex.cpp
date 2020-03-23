//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE hex_encoding_test

#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>

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

static const std::unordered_map<std::string, std::string> upper_valid_data_map = {{"ABCD", "41424344"},
                                                                                  {"AAAA", "41414141"},
                                                                                  {"f", "66"},
                                                                                  {"foo", "666F6F"},
                                                                                  {"foofoo", "666F6F666F6F"}};

static const std::unordered_map<std::string, std::string> lower_valid_data_map = {{"ABCD", "41424344"},
                                                                                  {"AAAA", "41414141"},
                                                                                  {"f", "66"},
                                                                                  {"foofoo", "666f6f666f6f"}};

static const std::unordered_map<std::string, std::string> invalid_data_map;

BOOST_AUTO_TEST_SUITE(hex_codec_algorithm_test_suite)

BOOST_DATA_TEST_CASE(hex_upper_range_range_encode, boost::unit_test::data::make(upper_valid_data_map), array_element) {
    std::string result = encode<hex<mode::upper>>(array_element.first);
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_upper_range_range_decode, boost::unit_test::data::make(upper_valid_data_map), array_element) {
    std::string result = decode<hex<mode::upper>>(array_element.second);
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_range_encode, boost::unit_test::data::make(upper_valid_data_map),
                     array_element) {
    std::string result = encode<hex<mode::upper>>(array_element.first.begin(), array_element.first.end());
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_range_decode, boost::unit_test::data::make(upper_valid_data_map),
                     array_element) {
    std::string result = decode<hex<mode::upper>>(array_element.second.begin(), array_element.second.end());
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_upper_range_iterator_encode, boost::unit_test::data::make(upper_valid_data_map),
                     array_element) {
    std::string result;
    encode<hex<mode::upper>>(array_element.first, std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_upper_range_iterator_decode, boost::unit_test::data::make(upper_valid_data_map),
                     array_element) {
    std::string result;
    decode<hex<mode::upper>>(array_element.second, std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_iterator_encode, boost::unit_test::data::make(upper_valid_data_map),
                     array_element) {
    std::string result;
    encode<hex<mode::upper>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_upper_iterator_iterator_decode, boost::unit_test::data::make(upper_valid_data_map),
                     array_element) {
    std::string result;
    decode<hex<mode::upper>>(array_element.second.begin(), array_element.second.end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_range_range_encode, boost::unit_test::data::make(lower_valid_data_map), array_element) {
    std::string result = encode<hex<mode::lower>>(array_element.first);
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_lower_range_range_decode, boost::unit_test::data::make(lower_valid_data_map), array_element) {
    std::string result = decode<hex<mode::lower>>(array_element.second);
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_range_encode, boost::unit_test::data::make(lower_valid_data_map),
                     array_element) {
    std::string result = encode<hex<mode::lower>>(array_element.first.begin(), array_element.first.end());
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_range_decode, boost::unit_test::data::make(lower_valid_data_map),
                     array_element) {
    std::string result = decode<hex<mode::lower>>(array_element.second.begin(), array_element.second.end());
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_range_iterator_encode, boost::unit_test::data::make(lower_valid_data_map),
                     array_element) {
    std::string result;
    encode<hex<mode::lower>>(array_element.first, std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_lower_range_iterator_decode, boost::unit_test::data::make(lower_valid_data_map),
                     array_element) {
    std::string result;
    decode<hex<mode::lower>>(array_element.second, std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_iterator_encode, boost::unit_test::data::make(lower_valid_data_map),
                     array_element) {
    std::string result;
    encode<hex<mode::lower>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.second);
}

BOOST_DATA_TEST_CASE(hex_lower_iterator_iterator_decode, boost::unit_test::data::make(lower_valid_data_map),
                     array_element) {
    std::string result;
    decode<hex<mode::lower>>(array_element.second.begin(), array_element.second.end(), std::back_inserter(result));
    BOOST_CHECK_EQUAL(result, array_element.first);
}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(hex_codec_adaptor_test_suite)
//
//    BOOST_DATA_TEST_CASE(hex_upper_range_encode, boost::unit_test::data::make(upper_valid_data_map), array_element) {
//        typedef hex<mode::upper> Codec;
//        typedef typename range_compressor_traits<typename Codec::stream_encoder_type,
//                decltype(array_element.first)>::type CompressorState;
//
//        BOOST_CHECK_EQUAL((array_element.first | adaptors::encoded<Codec, CompressorState>()), array_element.second);
//    }
//
//    BOOST_DATA_TEST_CASE(hex_upper_range_decode, boost::unit_test::data::make(upper_valid_data_map), array_element) {
//        typedef hex<mode::upper> Codec;
//        typedef typename range_compressor_traits<typename Codec::stream_encoder_type,
//                decltype(array_element.first)>::type CompressorState;
//
//        BOOST_CHECK_EQUAL((array_element.second | adaptors::decoded<Codec, CompressorState>()), array_element.first);
//    }
//
// BOOST_AUTO_TEST_SUITE_END()

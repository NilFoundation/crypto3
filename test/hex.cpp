//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE hex_encoding_test

#include <string>
#include <iterator>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

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

const char *test_data = "data/hex.json";

boost::property_tree::ptree mode_data(const char *mode) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(mode);

    return string_data;
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

// BOOST_AUTO_TEST_SUITE(hex_codec_adaptor_test_suite)
//
//    BOOST_DATA_TEST_CASE(hex_upper_range_encode, mode_data("upper_mode"), array_element) {
//        typedef hex<mode::upper> Codec;
//        typedef typename range_compressor_traits<typename Codec::stream_encoder_type,
//                decltype(array_element.first)>::type CompressorState;
//
//        BOOST_CHECK_EQUAL((array_element.first | adaptors::encoded<Codec, CompressorState>()), array_element.second.data());
//    }
//
//    BOOST_DATA_TEST_CASE(hex_upper_range_decode, mode_data("upper_mode"), array_element) {
//        typedef hex<mode::upper> Codec;
//        typedef typename range_compressor_traits<typename Codec::stream_encoder_type,
//                decltype(array_element.first)>::type CompressorState;
//
//        BOOST_CHECK_EQUAL((array_element.second.data() | adaptors::decoded<Codec, CompressorState>()), array_element.first);
//    }
//
// BOOST_AUTO_TEST_SUITE_END()

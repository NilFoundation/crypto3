//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE base_codec_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>

#include <nil/crypto3/codec/base.hpp>

using namespace nil::crypto3::codec;
using namespace nil::crypto3;

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

typedef std::unordered_map<std::string, std::vector<uint8_t>> byte_vector_data_t;
typedef std::unordered_map<std::string, std::string> string_data_t;

typedef std::unordered_map<std::string, std::vector<uint8_t>>::value_type byte_vector_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_data_value)

typedef std::vector<uint8_t> byte_vector_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_t)

static const byte_vector_data_t base64_valid_data = {
    {"Zg==", {0x66}},
    {"Zm8=", {0x66, 0x6F}},
    {"Zm9v", {0x66, 0x6F, 0x6F}},
    {"aGVsbG8gd29ybGQ=", {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64}},
    {"aGVsbG8gd29ybGQh", {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21}},
    {"SGVsbG8sIHdvcmxkLg==", {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2E}},
    {"VGhlIDEyIGNoYXJz", {0x54, 0x68, 0x65, 0x20, 0x31, 0x32, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73}},
    {"VGhlIDEzIGNoYXJzLg==", {0x54, 0x68, 0x65, 0x20, 0x31, 0x33, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E}},
    {"VGhlIDE0IGNoYXJzLi4=", {0x54, 0x68, 0x65, 0x20, 0x31, 0x34, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E, 0x2E}},
    {"VGhlIDE1IGNoYXJzLi4u",
     {0x54, 0x68, 0x65, 0x20, 0x31, 0x35, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E, 0x2E, 0x2E}},
    {"QW4gVVRGLTggdXVtbDogw7w=",
     {0x41, 0x6E, 0x20, 0x55, 0x54, 0x46, 0x2D, 0x38, 0x20, 0x75, 0x75, 0x6D, 0x6C, 0x3A, 0x20, 0xC3, 0xBC}},
    {"V2VpcmQgR2VybWFuIDIgYnl0ZSB0aGluZzogw58u",
     {0x57, 0x65, 0x69, 0x72, 0x64, 0x20, 0x47, 0x65, 0x72, 0x6D, 0x61, 0x6E, 0x20, 0x32, 0x20,
      0x62, 0x79, 0x74, 0x65, 0x20, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0xC3, 0x9F, 0x2E}},
    {"mw==", {0x9B}},
    {"HGA=", {0x1C, 0x60}},
    {"gTS9", {0x81, 0x34, 0xBD}},
    {"Xmz/3g==", {0x5E, 0x6C, 0xFF, 0xDE}},
    {"ss3w3H8=", {0xb2, 0xcd, 0xf0, 0xdc, 0x7f}},
    {"/FYt2tQO", {0xfc, 0x56, 0x2d, 0xda, 0xd4, 0x0e}},
    {"KbIyLohB6A==", {0x29, 0xb2, 0x32, 0x2e, 0x88, 0x41, 0xe8}},
    {"Dw/O2Ul6r5I=", {0x0f, 0x0f, 0xce, 0xd9, 0x49, 0x7a, 0xaf, 0x92}},
    {"Jw+xiYKADaZA", {0x27, 0x0f, 0xb1, 0x89, 0x82, 0x80, 0x0d, 0xa6, 0x40}}};

static const std::vector<std::string> base_invalid_data = {"ZOOL!isnotvalidbase64", "Neitheris:this?"};

static const byte_vector_data_t base58_valid_data = {
    {"Z", {0x20}},
    {"n", {0x2d}},
    {"q", {0x30}},
    {"r", {0x31}},
    {"z", {0x39}},
    {"4SU", {0x2d, 0x31}},
    {"4k8", {0x31, 0x31}},
    {"ZiCa", {0x61, 0x62, 0x63}},
    {"3mJr7AoUXx2Wqd", {0x31, 0x32, 0x33, 0x34, 0x35, 0x39, 0x38, 0x37, 0x36, 0x30}},
    {"3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
     {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
      0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a}},
    {"16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", {0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E,
                                           0x5E, 0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B, 0xEE, 0xD6, 0x19, 0x67, 0xF6}},
    {"1ZiCa", {0x00, 0x61, 0x62, 0x63}},
    {"11ZiCa", {0x00, 0x00, 0x61, 0x62, 0x63}},
    {"111ZiCa", {0x00, 0x00, 0x00, 0x61, 0x62, 0x63}},
    {"1111ZiCa", {0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63}}};

static const std::vector<std::string> base_58_invalid_data = {
    "0", "O", "I", "l", "3mJr0", "O3yxU", "3sNI", "4kl8", "s!5<", "t$@mX<*", "AreYouEvenLookingAtThese?"};

static const byte_vector_data_t base32_valid_data = {
    {"MY======", {0x66}},
    {"MZXQ====", {0x66, 0x6F}},
    {"MZXW6===", {0x66, 0x6F, 0x6F}},
    {"MZXW6ZQ=", {0x66, 0x6F, 0x6F, 0x66}},
    {"NBSWY3DPEB3W64TMMQ======", {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64}},
    {"NBSWY3DPEB3W64TMMQQQ====", {0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21}},
    {"JBSWY3DPFQQHO33SNRSC4===", {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2E}},
    {"KRUGKIBRGIQGG2DBOJZQ====", {0x54, 0x68, 0x65, 0x20, 0x31, 0x32, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73}},
    {"KRUGKIBRGMQGG2DBOJZS4===", {0x54, 0x68, 0x65, 0x20, 0x31, 0x33, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E}},
    {"KRUGKIBRGQQGG2DBOJZS4LQ=", {0x54, 0x68, 0x65, 0x20, 0x31, 0x34, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E, 0x2E}},
    {"KRUGKIBRGUQGG2DBOJZS4LRO",
     {0x54, 0x68, 0x65, 0x20, 0x31, 0x35, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x2E, 0x2E, 0x2E}},
    {"IFXCAVKUIYWTQIDVOVWWYORAYO6A====",
     {0x41, 0x6E, 0x20, 0x55, 0x54, 0x46, 0x2D, 0x38, 0x20, 0x75, 0x75, 0x6D, 0x6C, 0x3A, 0x20, 0xC3, 0xBC}},
    {"K5SWS4TEEBDWK4TNMFXCAMRAMJ4XIZJAORUGS3THHIQMHHZO",
     {0x57, 0x65, 0x69, 0x72, 0x64, 0x20, 0x47, 0x65, 0x72, 0x6D, 0x61, 0x6E, 0x20, 0x32, 0x20,
      0x62, 0x79, 0x74, 0x65, 0x20, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0xC3, 0x9F, 0x2E}},
    {"TM======", {0x9B}},
    {"DRQA====", {0x1C, 0x60}},
    {"QE2L2===", {0x81, 0x34, 0xBD}},
    {"LZWP7XQ=", {0x5E, 0x6C, 0xFF, 0xDE}},
    {"WLG7BXD7", {0xb2, 0xcd, 0xf0, 0xdc, 0x7f}},
    {"7RLC3WWUBY======", {0xfc, 0x56, 0x2d, 0xda, 0xd4, 0x0e}},
    {"FGZDELUIIHUA====", {0x29, 0xb2, 0x32, 0x2e, 0x88, 0x41, 0xe8}},
    {"B4H45WKJPKXZE===", {0x0f, 0x0f, 0xce, 0xd9, 0x49, 0x7a, 0xaf, 0x92}},
    {"E4H3DCMCQAG2MQA=", {0x27, 0x0f, 0xb1, 0x89, 0x82, 0x80, 0x0d, 0xa6, 0x40}}};

BOOST_AUTO_TEST_SUITE(base32_codec_test_suite)

BOOST_DATA_TEST_CASE(base32_single_range_encode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::string out = encode<base<32>>(array_element.second);

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_single_range_decode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::vector<uint8_t> out = decode<base<32>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base32_range_encode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::vector<uint8_t> out;
    encode<base<32>>(array_element.second, std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base32_range_decode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::vector<uint8_t> out;
    decode<base<32>>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base32_iterator_range_encode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::vector<uint8_t> out;
    encode<base<32>>(array_element.second.begin(), array_element.second.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base32_iterator_range_decode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::vector<uint8_t> out;
    decode<base<32>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base32_decode_failure, boost::unit_test::data::make(base_invalid_data), array_element) {
    BOOST_REQUIRE_THROW(decode<base<32>>(array_element), base_decode_error<32>);
}

BOOST_DATA_TEST_CASE(base32_alias_single_range_encode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::string out = encode<base32>(array_element.second);

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_alias_range_encode, boost::unit_test::data::make(base32_valid_data), array_element) {
    std::vector<uint8_t> out;
    encode<base32>(array_element.second, std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base32_alias_iterator_range_encode, boost::unit_test::data::make(base32_valid_data),
                     array_element) {
    std::vector<uint8_t> out;
    encode<base32>(array_element.second.begin(), array_element.second.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base32_alias_iterator_range_decode, boost::unit_test::data::make(base32_valid_data),
                     array_element) {
    std::vector<uint8_t> out;
    decode<base32>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base32_alias_decode_failure, boost::unit_test::data::make(base_invalid_data), array_element) {
    BOOST_REQUIRE_THROW(decode<base32>(array_element), base_decode_error<32>);
}

BOOST_DATA_TEST_CASE(base32_accumulator_encode, boost::unit_test::data::make(base32_valid_data), array_element) {
    typedef typename base<32>::stream_encoder_type codec_mode;
    typedef codec_accumulator<codec_mode> accumulator_type;

    accumulator_type acc;

    for (const auto &c : array_element.second) {
        acc(c);
    }

    auto res = accumulators::extract::codec<codec_mode>(acc);
    BOOST_CHECK_EQUAL(array_element.first, std::string(res.begin(), res.end()));
}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(base58_codec_test_suite)
//
//    BOOST_DATA_TEST_CASE(base58_single_range_encode, boost::unit_test::data::make(base58_valid_data), array_element) {
//        std::string out = encode<base<58>>(array_element.second);
//
//        BOOST_CHECK_EQUAL(out, array_element.first);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_range_encode, boost::unit_test::data::make(base58_valid_data), array_element) {
//        std::vector<uint8_t> out;
//        encode<base<58>>(array_element.second, std::back_inserter(out));
//
//        BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_iterator_range_encode, boost::unit_test::data::make(base58_valid_data), array_element)
//    {
//        std::vector<uint8_t> out;
//        encode<base<58>>(array_element.second.begin(), array_element.second.end(), std::back_inserter(out));
//
//        BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_iterator_range_decode, boost::unit_test::data::make(base58_valid_data), array_element)
//    {
//        std::vector<uint8_t> out;
//        decode<base<58>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
//        BOOST_CHECK_EQUAL(out, array_element.second);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_decode_failure, boost::unit_test::data::make(base_invalid_data), array_element) {
//        BOOST_REQUIRE_THROW(decode<base<58>>(array_element), base_decode_error<58>);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_alias_single_range_encode, boost::unit_test::data::make(base58_valid_data),
//            array_element) {
//        std::vector<uint8_t> out = encode<base58>(array_element.second);
//
//        BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_alias_range_encode, boost::unit_test::data::make(base58_valid_data), array_element) {
//        std::vector<uint8_t> out;
//        encode<base58>(array_element.second, std::back_inserter(out));
//
//        BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_alias_range_decode, boost::unit_test::data::make(base58_valid_data), array_element) {
//        std::vector<uint8_t> out;
//        decode<base58>(array_element.first, std::back_inserter(out));
//
//        BOOST_CHECK_EQUAL(out, array_element.second);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_alias_iterator_range_encode, boost::unit_test::data::make(base58_valid_data),
//            array_element) {
//        std::vector<uint8_t> out;
//        encode<base58>(array_element.second.begin(), array_element.second.end(), std::back_inserter(out));
//
//        BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_alias_iterator_range_decode, boost::unit_test::data::make(base58_valid_data),
//            array_element) {
//        std::vector<uint8_t> out;
//        decode<base58>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
//        BOOST_CHECK_EQUAL(out, array_element.second);
//    }
//
//    BOOST_DATA_TEST_CASE(base58_alias_decode_failure, boost::unit_test::data::make(base_58_invalid_data),
//            array_element) {
//        BOOST_REQUIRE_THROW(decode<base58>(array_element), base_decode_error<58>);
//    }
//
// BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(base64_codec_test_suite)

BOOST_DATA_TEST_CASE(base64_single_range_encode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::string out = encode<base<64>>(array_element.second);

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_range_encode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::vector<uint8_t> out;
    encode<base<64>>(array_element.second, std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base64_iterator_range_encode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::vector<uint8_t> out;
    encode<base<64>>(array_element.second.begin(), array_element.second.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base64_iterator_range_decode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::vector<uint8_t> out;
    decode<base<64>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base64_decode_failure, boost::unit_test::data::make(base_invalid_data), array_element) {
    BOOST_REQUIRE_THROW(decode<base<64>>(array_element), base_decode_error<64>);
}

BOOST_DATA_TEST_CASE(base64_alias_single_range_encode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::vector<uint8_t> out = encode<base64>(array_element.second);

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base64_alias_range_encode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::vector<uint8_t> out;
    encode<base64>(array_element.second, std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base64_alias_range_decode, boost::unit_test::data::make(base64_valid_data), array_element) {
    std::vector<uint8_t> out;
    decode<base64>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base64_alias_iterator_range_encode, boost::unit_test::data::make(base64_valid_data),
                     array_element) {
    std::vector<uint8_t> out;
    encode<base64>(array_element.second.begin(), array_element.second.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(std::string(out.begin(), out.end()), array_element.first);
}

BOOST_DATA_TEST_CASE(base64_alias_iterator_range_decode, boost::unit_test::data::make(base64_valid_data),
                     array_element) {
    std::vector<uint8_t> out;
    decode<base64>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_DATA_TEST_CASE(base64_alias_decode_failure, boost::unit_test::data::make(base_invalid_data), array_element) {
    BOOST_REQUIRE_THROW(decode<base64>(array_element), base_decode_error<64>);
}

BOOST_AUTO_TEST_SUITE_END()

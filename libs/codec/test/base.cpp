//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Moskvin Aleksey <zerg1996@yandex.ru>
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

#define BOOST_TEST_MODULE base_codec_test

#include <iostream>
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

#include <nil/crypto3/codec/base.hpp>

using namespace nil::crypto3::codec;
using namespace nil::crypto3;

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

const char *test_data = "data/base.json";

boost::property_tree::ptree base_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);

    return root_data.get_child(child_name);
}

BOOST_AUTO_TEST_SUITE(base32_codec_data_driven_test_suite)

    BOOST_DATA_TEST_CASE(base32_single_range_adaptor_encode, base_data("base_32"), array_element) {
        std::string enc = array_element.first | adaptors::encoded<base<32>>;
        std::string dec = array_element.second.data() | adaptors::decoded<base<32>>;

        BOOST_CHECK_EQUAL(enc, array_element.second.data());
        BOOST_CHECK_EQUAL(dec, array_element.first.data());
    }

BOOST_DATA_TEST_CASE(base32_single_range_encode, base_data("base_32"), array_element) {
    std::string out = encode<base<32>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base32_single_range_decode, base_data("base_32"), array_element) {
    std::string out = decode<base<32>>(array_element.second.data());

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_range_encode, base_data("base_32"), array_element) {
    std::string out;
    encode<base<32>>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base32_range_decode, base_data("base_32"), array_element) {
    std::string out;
    decode<base<32>>(array_element.second.data(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_iterator_range_encode, base_data("base_32"), array_element) {
    std::string out;
    encode<base<32>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base32_iterator_range_decode, base_data("base_32"), array_element) {
    std::string out;
    decode<base<32>>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_decode_failure, base_data("base_invalid"), array_element) {
    BOOST_REQUIRE_THROW(decode<base<32>>(array_element.second.data()), base_decode_error<32>);
}

BOOST_DATA_TEST_CASE(base32_alias_single_range_encode, base_data("base_32"), array_element) {
    std::string out = encode<base32>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base32_alias_single_range_decode, base_data("base_32"), array_element) {
    std::string out = decode<base32>(array_element.second.data());

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_alias_range_encode, base_data("base_32"), array_element) {
    std::string out;
    encode<base32>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base32_alias_range_decode, base_data("base_32"), array_element) {
    std::string out;
    decode<base32>(array_element.second.data(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_alias_iterator_range_encode, base_data("base_32"), array_element) {
    std::string out;
    encode<base32>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base32_alias_iterator_range_decode, base_data("base_32"), array_element) {
    std::string out;
    decode<base32>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base32_alias_decode_failure, base_data("base_invalid"), array_element) {
    BOOST_REQUIRE_THROW(decode<base32>(array_element.second.data()), base_decode_error<32>);
}

BOOST_DATA_TEST_CASE(base32_accumulator_encode, base_data("base_32"), array_element) {
    typedef typename base<32>::stream_encoder_type codec_mode;
    typedef codec::accumulator_set<codec_mode> accumulator_type;

    accumulator_type acc;

    for (const auto &c : array_element.first) {
        acc(c);
    }

    auto res = accumulators::extract::codec<codec_mode>(acc);
    BOOST_CHECK_EQUAL(std::string(res.begin(), res.end()), array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(base58_codec_data_driven_test_suite)

    BOOST_DATA_TEST_CASE(base58_single_range_adaptor_encode, base_data("base_58"), array_element) {
        std::string enc = array_element.first | adaptors::encoded<base<58>>;
        std::string dec = array_element.second.data() | adaptors::decoded<base<58>>;

        BOOST_CHECK_EQUAL(enc, array_element.second.data());
        BOOST_CHECK_EQUAL(dec, array_element.first.data());
    }

BOOST_DATA_TEST_CASE(base58_single_range_encode, base_data("base_58"), array_element) {
    std::string out = encode<base<58>>(array_element.first);
    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base58_single_range_decode, base_data("base_58"), array_element) {
    std::string out = decode<base<58>>(array_element.second.data());
    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base58_range_encode, base_data("base_58"), array_element) {
    std::string out;
    encode<base<58>>(array_element.first, std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base58_range_decode, base_data("base_58"), array_element) {
    std::string out;
    decode<base<58>>(array_element.second.data(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base58_iterator_range_encode, base_data("base_58"), array_element) {
    std::string out;
    encode<base<58>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base58_iterator_range_decode, base_data("base_58"), array_element) {
    std::string out;
    decode<base<58>>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base58_decode_failure, base_data("base_58_invalid"), array_element) {
    std::string out;
    BOOST_REQUIRE_THROW(decode<base<58>>(array_element.second.data().begin(), array_element.second.data().end(),
                                         std::back_inserter(out)),
                        base_decode_error<58>);
}

BOOST_DATA_TEST_CASE(base58_alias_single_range_encode, base_data("base_58"), array_element) {
    std::string out = encode<base58>(array_element.first);
    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base58_alias_single_range_decode, base_data("base_58"), array_element) {
    std::string out = decode<base58>(array_element.second.data());
    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base58_alias_range_encode, base_data("base_58"), array_element) {
    std::string out;
    encode<base58>(array_element.first, std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base58_alias_range_decode, base_data("base_58"), array_element) {
    std::string out;
    decode<base58>(array_element.second.data(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base58_alias_iterator_range_encode, base_data("base_58"), array_element) {
    std::string out;
    encode<base58>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base58_alias_iterator_range_decode, base_data("base_58"), array_element) {
    std::string out;
    decode<base58>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out));
    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base58_alias_decode_failure, base_data("base_58_invalid"), array_element) {
    std::string out;
    BOOST_REQUIRE_THROW(
        decode<base58>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out)),
        base_decode_error<58>);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(base64_codec_data_driven_test_suite)

    BOOST_DATA_TEST_CASE(base64_single_range_adaptor_encode, base_data("base_64"), array_element) {
        std::string enc = array_element.first | adaptors::encoded<base<64>>;
        std::string dec = array_element.second.data() | adaptors::decoded<base<64>>;

        BOOST_CHECK_EQUAL(enc, array_element.second.data());
        BOOST_CHECK_EQUAL(dec, array_element.first.data());
    }

BOOST_DATA_TEST_CASE(base64_single_range_encode, base_data("base_64"), array_element) {
    std::string out = encode<base<64>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base64_single_range_decode, base_data("base_64"), array_element) {
    std::string out = decode<base<64>>(array_element.second.data());

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_range_encode, base_data("base_64"), array_element) {
    std::string out;
    encode<base<64>>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base64_range_decode, base_data("base_64"), array_element) {
    std::string out;
    decode<base<64>>(array_element.second.data(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_iterator_range_encode, base_data("base_64"), array_element) {
    std::string out;
    encode<base<64>>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base64_iterator_range_decode, base_data("base_64"), array_element) {
    std::string out;
    decode<base<64>>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_decode_failure, base_data("base_invalid"), array_element) {
    BOOST_REQUIRE_THROW(decode<base<64>>(array_element.second.data()), base_decode_error<64>);
}

BOOST_DATA_TEST_CASE(base64_alias_single_range_encode, base_data("base_64"), array_element) {
    std::string out = encode<base64>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base64_alias_single_range_decode, base_data("base_64"), array_element) {
    std::string out = decode<base64>(array_element.second.data());

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_alias_range_encode, base_data("base_64"), array_element) {
    std::string out;
    encode<base64>(array_element.first, std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base64_alias_range_decode, base_data("base_64"), array_element) {
    std::string out;
    decode<base64>(array_element.second.data(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_alias_iterator_range_encode, base_data("base_64"), array_element) {
    std::string out;
    encode<base64>(array_element.first.begin(), array_element.first.end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(base64_alias_iterator_range_decode, base_data("base_64"), array_element) {
    std::string out;
    decode<base64>(array_element.second.data().begin(), array_element.second.data().end(), std::back_inserter(out));

    BOOST_CHECK_EQUAL(out, array_element.first);
}

BOOST_DATA_TEST_CASE(base64_alias_decode_failure, base_data("base_invalid"), array_element) {
    BOOST_REQUIRE_THROW(decode<base64>(array_element.second.data()), base_decode_error<64>);
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

BOOST_AUTO_TEST_SUITE(base32_codec_random_data_test_suite)

BOOST_DATA_TEST_CASE(base32_single_range_random_encode_decode,
                     boost::unit_test::data::random(std::numeric_limits<std::uintmax_t>::min(),
                                                    std::numeric_limits<std::uintmax_t>::max()) ^
                         boost::unit_test::data::xrange(std::numeric_limits<std::uint8_t>::max()),
                     random_sample, index) {
    std::array<std::uint8_t, sizeof(decltype(random_sample))> arr = to_byte_array(random_sample);
    arr[arr.size() - 1] = std::max((std::uint8_t)1, arr[arr.size() - 1]);    // Compliant with RFC 4648
    std::vector<std::uint8_t> enc = encode<base<32>>(arr);
    std::vector<std::uint8_t> out = decode<base<32>>(enc);
    BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(), arr.begin(), arr.end());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(base58_codec_random_data_test_suite)

BOOST_DATA_TEST_CASE(base58_single_range_random_encode_decode,
                     boost::unit_test::data::random(std::numeric_limits<std::uintmax_t>::min(),
                                                    std::numeric_limits<std::uintmax_t>::max()) ^
                         boost::unit_test::data::xrange(std::numeric_limits<std::uint8_t>::max()),
                     random_sample, index) {
    std::array<std::uint8_t, sizeof(decltype(random_sample))> arr = to_byte_array(random_sample);
    for (auto i : arr) {
        std::cout << (int)i << ' ';
    }
    std::cout << std::endl;
    std::vector<std::uint8_t> enc = encode<base<58>>(arr);
    for (auto i : enc) {
        std::cout << (int)i << ' ';
    }
    std::cout << std::endl;
    std::vector<std::uint8_t> out = decode<base<58>>(enc);
    BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(), arr.begin(), arr.end());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(base64_codec_random_data_test_suite)

BOOST_DATA_TEST_CASE(base64_single_range_random_encode_decode,
                     boost::unit_test::data::random(std::numeric_limits<std::uintmax_t>::min(),
                                                    std::numeric_limits<std::uintmax_t>::max()) ^
                         boost::unit_test::data::xrange(std::numeric_limits<std::uint8_t>::max()),
                     random_sample, index) {
    std::array<std::uint8_t, sizeof(decltype(random_sample))> arr = to_byte_array(random_sample);
    arr[arr.size() - 1] = std::max((std::uint8_t)1, arr[arr.size() - 1]);    // Compliant with RFC 4648
    std::vector<std::uint8_t> enc = encode<base<64>>(arr);
    std::vector<std::uint8_t> out = decode<base<64>>(enc);

    BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(), arr.begin(), arr.end());
}

BOOST_AUTO_TEST_SUITE_END()

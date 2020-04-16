//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sha_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/sha.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

using namespace nil::crypto3::hash;
using namespace nil::crypto3::accumulators;

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
}    // namespace boost

BOOST_TEST_DONT_PRINT_LOG_VALUE(sha::construction::type::digest_type)

class fixture {
public:
    accumulator_set<sha> acc;
    typedef sha hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/sha.json";

boost::property_tree::ptree string_data() {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data; 
}

BOOST_AUTO_TEST_SUITE(sha_stream_processor_filedriven_test_suite)

BOOST_DATA_TEST_CASE(sha_string_various_range_value_hash, string_data(), array_element) {
    std::string out = hash<sha>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha_string_various_itr_value_hash, string_data(), array_element) {
    std::string out = hash<sha>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha_stream_processor_test_suite)

BOOST_AUTO_TEST_CASE(sha_shortmsg_byte) {
	// https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/NIST.FIPS.180.pdf
    // Appendix A: "abc"
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    sha::digest_type d = hash<sha>(a);

    BOOST_CHECK_EQUAL("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(sha_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(sha_accumulator1, fixture) {
    hash_t::construction::type::block_type m = {{}};

    m[0] = 0x61626300;
    acc(m, nil::crypto3::accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha_accumulator2, fixture) {
	// Appendix B: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    hash_t::construction::type::block_type m = {
        {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d6e6f70, 0x6e6f7071, 0x00000000, 0x00000000}};
    acc(m, nil::crypto3::accumulators::bits = 512 - 64);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("d2516ee1acfa5baf33dfc1c471e438449ef134c8", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha_preprocessor1) {
    accumulator_set<sha> acc;

    acc(0x61000000, nil::crypto3::accumulators::bits = 8);
    acc(0x62000000, nil::crypto3::accumulators::bits = 8);
    acc(0x63000000, nil::crypto3::accumulators::bits = 8);

    sha::digest_type s = extract::hash<sha>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha_preprocessor2) {
    // Appendix C: million repetitions of "a"
    accumulator_set<sha> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(0x61000000, nil::crypto3::accumulators::bits = 8);

    sha::digest_type s = extract::hash<sha>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("3232affa48628a26653b5aaa44541fd90d690603",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()
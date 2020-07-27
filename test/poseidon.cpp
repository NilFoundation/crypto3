//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE poseidon_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/adaptor/hashed.hpp>

#include <nil/crypto3/hash/poseidon.hpp>

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::poseidon::digest_type)

class fixture {
public:
    accumulator_set<hashes::poseidon> acc;
    typedef hashes::poseidon hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/poseidon.json";

boost::property_tree::ptree string_data() {
    boost::property_tree::ptree string_data;
    boost::property_tree::read_json(test_data, string_data);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(poseidon_stream_processor_data_driven_algorithm_test_suite)

BOOST_DATA_TEST_CASE(poseidon_string_various_range_value_hash, string_data(), array_element) {
    std::string out = hash<hashes::poseidon>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(poseidon_string_various_itr_value_hash, string_data(), array_element) {
    std::string out = hash<hashes::poseidon>(array_element.first.begin(), array_element.first.end());

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(poseidon_stream_processor_data_driven_adaptor_test_suite)

BOOST_DATA_TEST_CASE(poseidon_string_various_range_value_hash, string_data(), array_element) {
    std::string out = array_element.first | adaptors::hashed<hashes::poseidon>;

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

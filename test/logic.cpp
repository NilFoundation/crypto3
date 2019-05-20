//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE logic_encoding_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/codec/logic.hpp>

using namespace nil::crypto3::codec;

typedef std::unordered_map<std::string, std::string>::value_type string_data_value_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value_t)

typedef std::unordered_map<std::string, std::vector<uint8_t>>::value_type byte_vector_data_value_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_data_value_t)

typedef std::vector<uint8_t> byte_vector_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_t)

static const std::unordered_map<std::string, std::vector<uint8_t>> valid_data;

static const std::vector<std::string> invalid_data;

BOOST_AUTO_TEST_SUITE(logic_encode_test_suite)

    BOOST_DATA_TEST_CASE(logic_single_range_encode, boost::unit_test::data::make(valid_data), array_element) {

    }

BOOST_AUTO_TEST_SUITE_END()
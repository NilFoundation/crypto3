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
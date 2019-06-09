//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE keccak_test

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/hash/detail/primes.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

using namespace nil::crypto3::hash;

typedef std::vector<uint8_t> byte_vector_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_t)

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

typedef std::unordered_map<std::string, std::vector<uint8_t>>::value_type byte_data_value_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_data_value_t)

static const std::unordered_map<std::string, std::string> string_data = {{"\x2",                                                                              "00030003"},
                                                                         {"\x2\x4",                                                                           "000a0007"},
                                                                         {"",                                                                                 "00000001"},
                                                                         {"a",                                                                                "00620062"},
                                                                         {"abc",                                                                              "024d0127"},
                                                                         {"message digest",                                                                   "29750586"},
                                                                         {"abcdefghijklmnopqrstuvwxyz",                                                       "90860b20"},
                                                                         {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",                   "8adb150c"},
                                                                         {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "97b61069"}};

static const std::unordered_map<std::string, std::vector<uint8_t>> byte_data = {{"\x2",                                                                              {0x00, 0x03, 0x00, 0x03}},
                                                                                {"\x2\x4",                                                                           {0x00, 0x0a, 0x00, 0x07}},
                                                                                {"",                                                                                 {0x00, 0x00, 0x00, 0x01}},
                                                                                {"a",                                                                                {0x00, 0x62, 0x00, 0x62}},
                                                                                {"abc",                                                                              {0x02, 0x4d, 0x01, 0x27}},
                                                                                {"message digest",                                                                   {0x29, 0x75, 0x05, 0x86}},
                                                                                {"abcdefghijklmnopqrstuvwxyz",                                                       {0x90, 0x86, 0x0b, 0x20}},
                                                                                {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",                   {0x8a, 0xdb, 0x15, 0x0c}},
                                                                                {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", {0x97, 0xb6, 0x10, 0x69}}};

BOOST_AUTO_TEST_SUITE(keccak_test_suite)

    BOOST_DATA_TEST_CASE(keccak_range_itr_hash, boost::unit_test::data::make(byte_data), array_element) {

    }

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE twofish_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/twofish.hpp>


using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(twofish_test_suite)

BOOST_AUTO_TEST_CASE(twofish_128_1) {

    std::vector<char> input = {'\xd4', '\x91', '\xdb', '\x16', '\xe7', '\xb1', '\xc3', '\x9e', '\x86', '\xcb', '\x08', '\x6b', '\x78', '\x9f', '\x54', '\x19'};
    std::vector<char> key = {'\x9f', '\x58', '\x9f', '\x5c', '\xf6', '\x12', '\x2c', '\x32', '\xb6', '\xbf', '\xec', '\x2f', '\x2a', '\xe8', '\xc3', '\x5a'};

    std::string out = encrypt<block::twofish<128>>(input, key);
    
    BOOST_CHECK_EQUAL(out, "019f9809de1711858faac3a3ba20fbc3");
}

BOOST_AUTO_TEST_SUITE_END()
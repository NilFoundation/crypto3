//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE noekeon_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/noekeon.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(noekeon_test_suite)

BOOST_AUTO_TEST_CASE(noekeon_1) {

    std::vector<char> input = {'\xea', '\x02', '\x47', '\x14', '\xad', '\x5c', '\x4d', '\x84'};
    std::vector<char> key = {'\xba', '\x69', '\x33', '\x81', '\x92', '\x99', '\xc7', '\x16',
                             '\x99', '\xa9', '\x9f', '\x08', '\xf6', '\x78', '\x17', '\x8b'};

    std::string out = encrypt<block::noekeon>(input, key);

    BOOST_CHECK_EQUAL(out, "df1f9b251c0bf45f");
}

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE kasumi_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/kasumi.hpp>


using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(kasumi_test_suite)

BOOST_AUTO_TEST_CASE(kasumi_1) {

    std::vector<char> input = {'\xea', '\x02', '\x47', '\x14', '\xad', '\x5c', '\x4d', '\x84'};
    std::vector<char> key = {'\x2b', '\xd6', '\x45', '\x9f', '\x82', '\xc5', '\xb3', '\x00', '\x95', '\x2c', '\x49', '\x10', '\x48', '\x81', '\xff', '\x48'};

    std::string out = encrypt<block::kasumi>(input, key);
    
    BOOST_CHECK_EQUAL(out, "df1f9b251c0bf45f");
}

BOOST_AUTO_TEST_SUITE_END()
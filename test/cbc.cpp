//---------------------------------------------------------------------------//
//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE cbc_test

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/rijndael.hpp>

#include <nil/crypto3/modes/cbc.hpp>
#include <nil/crypto3/modes/padding.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

BOOST_AUTO_TEST_SUITE(cbc_mode_test_suite)

BOOST_AUTO_TEST_CASE(cbc_mode_test_case) {
    std::string plaintext = "000102030405060708090a0b0c0d0e0f", key = "00112233445566778899aabbccddeeff";
    std::string enc = encrypt<modes::cbc<rijndael<128, 128>, modes::padding::zeros>>(plaintext, key);
}

BOOST_AUTO_TEST_SUITE_END()
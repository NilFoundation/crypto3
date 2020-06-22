//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE des_cipher_test


#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/des.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

BOOST_TEST_DONT_PRINT_LOG_VALUE(block::des::block_type)

BOOST_AUTO_TEST_SUITE(shacal_test_suite)

BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt1) {
    typedef block::des bct;

    bct::block_type plaintext = {{0x059b5e08, 0x51cf143a}};

    bct::key_type key = {{0x0113b970, 0xfd34f2ce}};
    bct cipher(key);
    bct::block_type ciphertext = cipher.encrypt(plaintext);
    bct::block_type expected_ciphertext = {{0x86a560f10, 0xec6d85b}};

    BOOST_CHECK_EQUAL(ciphertext, expected_ciphertext);

    bct::block_type new_plaintext = cipher.decrypt(ciphertext);

    BOOST_CHECK_EQUAL(plaintext, new_plaintext);
}

BOOST_AUTO_TEST_SUITE_END()
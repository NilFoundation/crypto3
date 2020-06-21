//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE shacal_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/shacal1.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

BOOST_TEST_DONT_PRINT_LOG_VALUE(shacal1::block_type)

BOOST_AUTO_TEST_SUITE(shacal1_test_suite)

BOOST_AUTO_TEST_CASE(shacal1_single_block_encrypt1) {
    typedef block::shacal1 bct;

    // Test with the equivalent of SHA-1("")
    bct::block_type plaintext = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}};
    bct::key_type key = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    bct cipher(key);
    bct::block_type ciphertext = cipher.encrypt(plaintext);
    bct::block_type expected_ciphertext = {{0x72f480ed, 0x6e9d9f84, 0x999ae2f1, 0x852dc41a, 0xec052519}};

    BOOST_CHECK_EQUAL(ciphertext, expected_ciphertext);

    bct::block_type new_plaintext = cipher.decrypt(ciphertext);
    BOOST_CHECK_EQUAL(plaintext, new_plaintext);
}

BOOST_AUTO_TEST_SUITE_END()
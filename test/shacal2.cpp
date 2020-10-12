//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE shacal2_cipher_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/shacal2.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<256>::block_type)

BOOST_AUTO_TEST_SUITE(shacal_test_suite)

BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt1) {
    typedef block::shacal2<256> bct;

    // Test with the equivalent of SHA-256("")
    bct::block_type plaintext = {
        {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
    bct::key_type key = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    bct cipher(key);
    bct::block_type ciphertext = cipher.encrypt(plaintext);
    bct::block_type expected_ciphertext = {
        {0x79a6dddb, 0xdd946d8f, 0x5e8d0156, 0xf41fc3ea, 0xd69fef65, 0xc9962ac0, 0x8511bf70, 0x1c71eb3c}};

    BOOST_CHECK_EQUAL(ciphertext, expected_ciphertext);

    bct::block_type new_plaintext = cipher.decrypt(ciphertext);

    BOOST_CHECK_EQUAL(plaintext, new_plaintext);
}

BOOST_AUTO_TEST_SUITE_END()
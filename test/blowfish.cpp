//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
#define BOOST_TEST_MODULE blowfish_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/blowfish.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;
using namespace nil::crypto3::detail;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream&, P<K, V> const&) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

struct state_adder {
    template<typename T>
    void operator()(T &s1, T const &s2) {
        typedef typename T::size_type size_type;
        size_type n = (s2.size() < s1.size() ? s2.size() : s1.size());
        for (typename T::size_type i = 0; i < n; ++i) {
            s1[i] += s2[i];
        }
    }
};


BOOST_AUTO_TEST_SUITE(blowfish_test_suite)

BOOST_AUTO_TEST_CASE(blowfish_single_block_encrypt1) {
    typedef block::blowfish bct;

    // Test with the equivalent of SHA-1("")
    bct::block_type plaintext = {{0x004bd6ef, 0x09176062}};
    bct::key_type key = {{0x58402364, 0x1aba6176}};

    bct cipher(key);
    bct::block_type ciphertext = cipher.encrypt(plaintext);
    bct::block_type expected_ciphertext = {{0x452031c1, 0xe4fada8e}};

    BOOST_CHECK_EQUAL(ciphertext, expected_ciphertext);

    bct::block_type new_plaintext = cipher.decrypt(ciphertext);
    BOOST_CHECK_EQUAL(plaintext, new_plaintext);
}

BOOST_AUTO_TEST_SUITE_END()
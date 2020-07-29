//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ecdsa_test

#include <nil/crypto3/pubkey/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>

#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/pubkey/blinding.hpp>
#include <nil/crypto3/pubkey/cecpq1.hpp>
#include <nil/crypto3/pubkey/curve25519.hpp>
#include <nil/crypto3/pubkey/dh.hpp>
#include <nil/crypto3/pubkey/dlies.hpp>
#include <nil/crypto3/pubkey/dsa.hpp>
#include <nil/crypto3/pubkey/ecc_key.hpp>
#include <nil/crypto3/pubkey/ecdh.hpp>
#include <nil/crypto3/pubkey/ecdsa.hpp>
#include <nil/crypto3/pubkey/ecgdsa.hpp>
#include <nil/crypto3/pubkey/ecies.hpp>
#include <nil/crypto3/pubkey/eckcdsa.hpp>
#include <nil/crypto3/pubkey/ed25519.hpp>
#include <nil/crypto3/pubkey/elgamal.hpp>
#include <nil/crypto3/pubkey/gost_3410.hpp>
#include <nil/crypto3/pubkey/keypair.hpp>
#include <nil/crypto3/pubkey/mceliece.hpp>
#include <nil/crypto3/pubkey/newhope.hpp>
#include <nil/crypto3/pubkey/pbes2.hpp>
#include <nil/crypto3/pubkey/pem.hpp>
#include <nil/crypto3/pubkey/pk_keys.hpp>
#include <nil/crypto3/pubkey/pk_operations.hpp>
#include <nil/crypto3/pubkey/pk_ops_fwd.hpp>
#include <nil/crypto3/pubkey/pkcs8.hpp>
#include <nil/crypto3/pubkey/scheme.hpp>
#include <nil/crypto3/pubkey/rfc6979.hpp>
#include <nil/crypto3/pubkey/rsa.hpp>
#include <nil/crypto3/pubkey/sm2.hpp>
#include <nil/crypto3/pubkey/sm2_encrypt.hpp>
#include <nil/crypto3/pubkey/complexity.hpp>
#include <nil/crypto3/pubkey/x509_key.hppecdsa.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/static_assert.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <cstdio>
#include <cstring>

using namespace nil::crypto3::pubkey;

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

// BOOST_TEST_DONT_PRINT_LOG_VALUE(ecdsa::construction_type::digest_type)

static const std::unordered_map<std::string, std::string> string_data = {
    {"", "cdf26213a150dc3ecb610f18f6b38b46"},
    {"a", "86be7afa339d0fc7cfc785e72f578d33"},
    {"abc", "c14a12199c66e4ba84636b0f69144c77"},
    {"message digest", "9e327b3d6e523062afc1132d7df9d1b8"},
    {"abcdefghijklmnopqrstuvwxyz", "fd2aa607f71dc8f510714922b371834e"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "a1aa0689d0fafa2ddc22e88b49133a06"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d1e959eb179c911faea4624c60c5c702"}};

BOOST_AUTO_TEST_SUITE(ecdsa_test_suite)

BOOST_DATA_TEST_CASE(ecdsa_range_hash, boost::unit_test::data::make(string_data), array_element) {
    std::string out = sign(array_element.first, public_key<ecdsa>());

    BOOST_CHECK_EQUAL(out, array_element.second);
}

BOOST_AUTO_TEST_SUITE_END()
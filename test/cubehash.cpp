//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE cubehash_test

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/cubehash.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <string>
#include <unordered_map>
#include <cstdio>

using namespace nil::crypto3;

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

typedef hash::cubehash<16, 32, 512>::digest_type cubehash_hash_512_digest_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(cubehash_hash_512_digest_t)

typedef hash::cubehash<16, 32, 256>::digest_type cubehash_hash_256_digest_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(cubehash_hash_256_digest_t)

static const std::unordered_map<std::string, std::string> string_512_data = {
    {"",
     "4a1d00bbcfcb5a9562fb981e7f7db335"
     "0fe2658639d948b9d57452c22328bb32"
     "f468b072208450bad5ee178271408be0"
     "b16e5633ac8a1e3cf9864cfbfc8e043a"},
    {"a",
     "2b3fa7a97d1e369a469c9e5d5d4e52fe"
     "37bc8befb369dc0923372c2eae1d91ee"
     "a9f69407f433bb49ab6ceaeeea739bb7"
     "52c1e33f69eda9a479e5a5b941968c75"},
    {"abc",
     "f63d6fa89ca9fe7ab2e171be52cf193f"
     "0c8ac9f62bad297032c1e7571046791a"
     "7e8964e5c8d91880d6f9c2a54176b051"
     "98901047438e05ac4ef38d45c0282673"},
    {"message digest",
     "7542d158eb956be75911c15ee566c3b7"
     "e54493fe3b1616223b4b27543754b0bf"
     "aa840e5efb1f7d3b41b85bad7631f47d"
     "35c46e7e66c6f3771ae76da629f2df8b"},
    {"abcdefghijklmnopqrstuvwxyz",
     "8f2cf3bed40d6be82aa2d3204857f014"
     "4a8d616c999c2e3f98b47f7a60530bf0"
     "f8206620874cee7b233c941b8fd4746d"
     "bc8bdca2ef3dea1ee1c9c3b6ea02d79b"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "4fa279c9bf54119f9b743932f06a7334"
     "0e83bf88f8db0edf0bf09bc26383e4f3"
     "d3c8aa9d8406167a1d6f6c0f0dc65046"
     "55434924571fe900f36d79eacfbdc7f5"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "cd18a5048d961b62f270edd87f9cd5c4"
     "1d3970a2b6f763bc173a2b05b9637e5a"
     "15c77ea3cf9484b34f458cbf71708722"
     "b271bb1349a4a17b6dd065bde8f1dfc1"}};

static const std::unordered_map<std::string, std::string> string_256_data = {
    {"",
     "44c6de3ac6c73c391bf0906cb7482600"
     "ec06b216c7c54a2a8688a6a42676577d"},
    {"a",
     "251e622d2a9004212a9114f4a4eacbbe"
     "f11cfe2ee40e41ac8b033a1b499a53f6"},
    {"abc",
     "a220b4bf5023e750c2a34dcd5564a852"
     "3d32e17fab6fbe0f18a0b0bf5a65632b"},
    {"message digest",
     "da81a92056cf05a407517c0a61a89c7c"
     "6045593bfedd66d6733545f2d1b90d9a"},
    {"abcdefghijklmnopqrstuvwxyz",
     "27f9139ee6c7086b304c592595c8aaa3"
     "3be76fd112ce605bf5f956b00d1a0847"},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "a858626aa4cca75bbe02283f56f12a98"
     "7def23783a3d327de40f736f4ce92cc6"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
     "227bd791e19fadab25282433639a73de"
     "cfed5b69ecde8a0aee0766d879e13e7b"}};

BOOST_AUTO_TEST_SUITE(cubehash_test_suite)

BOOST_AUTO_TEST_CASE(cubehash_policy_test) {
    // Test of just the policy, equivalent to hashing an empty message
    typedef hash::detail::cubehash_policy<16, 32, 512> policy_type;
    policy_type::state_type s = policy_type::iv_generator()();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("initial s[0] = %.8x\n", s[0]);
#endif

    BOOST_CHECK_EQUAL(s[0], 0x2aea2a61);

    s[0] ^= 0x80;
    policy_type::transform_r(s);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("intrim s[0] = %.8x (empty message)\n", s[0]);
#endif

    BOOST_CHECK_EQUAL(s[0], 0x263a6ab2);

    s[31] ^= 1;
    policy_type::transform_10r(s);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("final s[0] = %.8x (empty message)\n", s[0]);
#endif

    BOOST_CHECK_EQUAL(s[0], 0xbb001d4a);
}

BOOST_AUTO_TEST_CASE(cubehash_various) {
    typedef hash::cubehash<16, 32, 512> hash_t;
    hash::accumulator_set<hash_t> acc;
    typedef hash_t::construction::type bht;

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("initial s[0] = %.8x\n", bh.state()[0]);
#endif

    bht::block_type b = {{0x80}};
    acc(b);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("intrim s[0] = %.8x (empty message)\n", bh.state()[0]);
#endif

    BOOST_CHECK_EQUAL(accumulators::extract::hash<hash_t>(acc)[0], 0x263a6ab2);

    hash_t::digest_type d = accumulators::extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL(
        "4a1d00bbcfcb5a9562fb981e7f7db335"
        "0fe2658639d948b9d57452c22328bb32"
        "f468b072208450bad5ee178271408be0"
        "b16e5633ac8a1e3cf9864cfbfc8e043a",
        d);
}

BOOST_DATA_TEST_CASE(cubehash512_range_hash, boost::unit_test::data::make(string_512_data), array_element) {
    typedef hash::cubehash<16, 32, 512> hash_t;

    hash_t::digest_type d;

    hash::hash<hash_t>(array_element.first, d.end());

    BOOST_CHECK_EQUAL(std::to_string(d).data(), array_element.second);
}

BOOST_DATA_TEST_CASE(cubehash512_iterator_range_hash, boost::unit_test::data::make(string_512_data), array_element) {
    typedef hash::cubehash<16, 32, 512> hash_t;

    hash_t::digest_type d;

    hash::hash<hash_t>(array_element.first.begin(), array_element.first.end(), d.end());

    BOOST_CHECK_EQUAL(std::to_string(d).data(), array_element.second);
}

BOOST_DATA_TEST_CASE(cubehash512_return_range_hash, boost::unit_test::data::make(string_512_data), array_element) {
    typedef hash::cubehash<16, 32, 512> hash_t;
    typename hash_t::digest_type d = hash::hash<hash_t>(array_element.first);

    BOOST_CHECK_EQUAL(std::to_string(d), array_element.second);
}

BOOST_AUTO_TEST_CASE(cubehash512_accumulator) {
    typedef hash::cubehash<16, 32, 512> hash_t;
    hash::accumulator_set<hash_t> acc;

    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }

    hash_t::digest_type d = accumulators::extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL(
        "b2255396660eb6d08cdfd5f391ff522a"
        "a81c874328e6c3b365a246e869e8f9f7"
        "16ba99e0440de770f2c97ebf301a5f84"
        "00bfff4ad4b107aa71419c84ae30814e",
        d);

    for (unsigned i = 0; i < 1000000000; ++i) {
        acc('a');
    }
    d = accumulators::extract::hash<hash_t>(acc);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL(
        "cad33236b5a4810ea619e069bb2beff1"
        "ccb4ec4577ecea0b269d2be299dcf137"
        "f38f1816df12051480a479f1ad264564"
        "7378e5cec558fbe7c4bce8357016c1c8",
        d);
}

BOOST_DATA_TEST_CASE(cubehash256_return_range_hash, boost::unit_test::data::make(string_256_data), array_element) {
    typedef hash::cubehash<16, 32, 256> hash_t;
    hash_t::digest_type d = hash::hash<hash_t>(array_element.first);

    BOOST_CHECK_EQUAL(std::to_string(d), array_element.second);
}

BOOST_AUTO_TEST_CASE(cubehash256_accumulator) {
    typedef hash::cubehash<16, 32, 256> hash_t;
    hash::accumulator_set<hash_t> acc;

    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    hash_t::digest_type d = accumulators::extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL(
        "bdaaff72d49f8d5a66e4760fc54c2587"
        "d909bd21811473d252e8589d30b34352",
        d);

    for (unsigned i = 0; i < 1000000000; ++i) {
        acc('a');
    }
    d = accumulators::extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL(
        "7ed524f063da37f9e38e5ad9bbb4db9f"
        "e4c09844c9d0a07b046284b17c4c901a",
        d);
}

BOOST_AUTO_TEST_SUITE_END()

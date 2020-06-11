//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE shacal2_cipher_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/hash/detail/block_stream_processor.hpp>
#include <nil/crypto3/hash/detail/davies_meyer_compressor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>

#include <nil/crypto3/block/shacal2.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<256>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<512>::block_type)

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

BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt2) {
    typedef block::shacal2<256> bct;
    typedef hash::davies_meyer_compressor<bct, state_adder> owcft;

    // Test with the equivalent of SHA-256("")
    owcft::state_type const H0 = {
        {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
    owcft::block_type block = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    owcft::state_type H = H0;
    owcft f;
    f.process_block(H, block);
    owcft::state_type const H1 = {
        {0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855}};

    BOOST_CHECK_EQUAL(H, H1);
}

struct shacal2_params_type {
    typedef typename stream_endian::big_octet_big_bit digest_endian;

    constexpr static const std::size_t length_bits = 64;
    constexpr static const std::size_t digest_bits = 256;
};

BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt3) {
    typedef block::shacal2<256> bct;
    typedef hash::davies_meyer_compressor<bct, state_adder> owcft;
    typedef hash::detail::merkle_damgard_padding<typename shacal2_params_type::digest_endian,
                                                 hash::detail::sha2_policy<256>>
        pt;
    typedef hash::merkle_damgard_construction<shacal2_params_type, hash::detail::sha2_policy<256>::iv_generator, owcft,
                                              pt>
        bht;

    // Test with the equivalent of SHA-256("")
    bht::block_type block = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    bht bh;
    bh.process_block(block);
    bht::digest_type h = bh.digest();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << h std::endl;
#endif

    const char *eh = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    BOOST_CHECK_EQUAL(eh, std::to_string(h).data());
}

BOOST_AUTO_TEST_CASE(shacal2_512_encrypt1) {
    constexpr static const std::size_t SHA = 512;

    hash::accumulator_set<hash::sha2<SHA>> acc;

    typename hash::sha2<SHA>::digest_type d = accumulators::extract::hash<hash::sha2<SHA>>(acc);
    printf("%s\n", std::to_string(d).data());
    const char *ed =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    BOOST_CHECK(!strcmp(ed, std::to_string(d).data()));
}

BOOST_AUTO_TEST_CASE(shacal2_512_encrypt2) {
    constexpr static const std::size_t SHA = 512;
    hash::accumulator_set<hash::sha2<SHA>> acc;

    acc('a');
    acc('b');
    acc('c');

    typename hash::sha2<SHA>::digest_type d = accumulators::extract::hash<hash::sha2<SHA>>(acc);

    printf("%s\n", std::to_string(d).data());
    const char *ed =
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    BOOST_CHECK(!strcmp(ed, std::to_string(d).data()));
}

BOOST_AUTO_TEST_CASE(shacal2_512_encrypt3) {
    constexpr static const std::size_t SHA = 512;
    hash::accumulator_set<hash::sha2<SHA>> acc;
    const char *m =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    for (const char *p = m; *p; ++p) {
        acc(*p);
    }
    typename hash::sha2<SHA>::digest_type d = accumulators::extract::hash<hash::sha2<SHA>>(acc);
    printf("%s\n", std::to_string(d).data());
    const char *ed =
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
    BOOST_CHECK(!strcmp(ed, std::to_string(d).data()));
}

BOOST_AUTO_TEST_CASE(shacal2_512_accumulator1) {
    constexpr static const std::size_t SHA = 512;
    hash::accumulator_set<hash::sha2<SHA>> acc;

    for (unsigned n = 1000000; n--;) {
        acc('a');
    }
    typename hash::sha2<SHA>::digest_type d = accumulators::extract::hash<hash::sha2<SHA>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    printf("%s\n", std::to_string(d).data());
#endif

    const char *ed =
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
    BOOST_CHECK_EQUAL(ed, std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(shacal2_512_accumulator2) {
    constexpr static const std::size_t SHA = 512;
    hash::accumulator_set<hash::sha2<SHA>> acc;

    // perl -e 'for ($x = 1000000000; $x--;) {print "a";}' | sha512sum
    for (unsigned n = 1000000000; n--;) {
        acc('a');
    }
    typename hash::sha2<SHA>::digest_type d = accumulators::extract::hash<hash::sha2<SHA>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    printf("%s\n", std::to_string(d).data());
#endif

    const char *ed =
        "7cc86d7e06edc6a2029b8c0fa0e3ffb013888fd360f8faf681c7cffd08eacffb"
        "f09ae159827fc6e4c03894e6ecf4616395d3479f80d66ed3ac81a64ea0445f32";
    BOOST_CHECK_EQUAL(ed, std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()
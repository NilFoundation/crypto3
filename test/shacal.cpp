//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
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

#include <nil/crypto3/hash/detail/sha1_policy.hpp>
#include <nil/crypto3/hash/detail/sha2_policy.hpp>

#include <nil/crypto3/hash/detail/merkle_damgard_state_preprocessor.hpp>
#include <nil/crypto3/hash/detail/davies_meyer_compressor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>

#include <nil/crypto3/block/shacal.hpp>
#include <nil/crypto3/block/shacal1.hpp>
#include <nil/crypto3/block/shacal2.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

using namespace nil::crypto3;

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

BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal1::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<256>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(block::shacal2<512>::block_type)

BOOST_AUTO_TEST_SUITE(shacal_test_suite)

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

    BOOST_AUTO_TEST_CASE(shacal1_single_block_encrypt2) {
        typedef block::shacal1 bct;
        typedef hash::davies_meyer_compressor<bct, state_adder> owcft;


        // Test with the equivalent of SHA-256("")
        owcft::state_type const H0 = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}};
        owcft::block_type block = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
        owcft::state_type H = H0;

        owcft f;
        f(H, block);
        owcft::state_type const H1 = {{0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709}};
        BOOST_CHECK_EQUAL(H, H1);
    }

    BOOST_AUTO_TEST_CASE(shacal1_single_block_encrypt3) {
        typedef block::shacal1 bct;
        typedef hash::davies_meyer_compressor<bct, state_adder> owcft;
        typedef hash::merkle_damgard_construction<nil::crypto3::hash::stream_endian::big_octet_big_bit, 160,
                                                  hash::detail::sha1_policy::iv_generator, owcft> bht;


        // Test with the equivalent of SHA-1("")
        bht::block_type block = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
        bht bh;
        bh.update(block);
        bht::digest_type h = bh.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << h.cstring() std::endl;
#endif

        const char *eh = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

        BOOST_CHECK_EQUAL(eh, std::to_string(h).data());
    }

    BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt1) {
        typedef block::shacal2<256> bct;

        // Test with the equivalent of SHA-256("")
        bct::block_type plaintext = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
        bct::key_type key = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
        bct cipher(key);
        bct::block_type ciphertext = cipher.encrypt(plaintext);
        bct::block_type expected_ciphertext = {{0x79a6dddb, 0xdd946d8f, 0x5e8d0156, 0xf41fc3ea, 0xd69fef65, 0xc9962ac0, 0x8511bf70, 0x1c71eb3c}};

        BOOST_CHECK_EQUAL(ciphertext, expected_ciphertext);

        bct::block_type new_plaintext = cipher.decrypt(ciphertext);

        BOOST_CHECK_EQUAL(plaintext, new_plaintext);
    }

    BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt2) {
        typedef block::shacal2<256> bct;
        typedef hash::davies_meyer_compressor<bct, state_adder> owcft;

        // Test with the equivalent of SHA-256("")
        owcft::state_type const H0 = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
        owcft::block_type block = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
        owcft::state_type H = H0;
        owcft f;
        f(H, block);
        owcft::state_type const H1 = {{0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855}};

        BOOST_CHECK_EQUAL(H, H1);
    }

    BOOST_AUTO_TEST_CASE(shacal2_single_block_encrypt3) {
        typedef block::shacal2<256> bct;
        typedef hash::davies_meyer_compressor<bct, state_adder> owcft;
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, 256,
                                                  hash::detail::sha2_policy<256>::iv_generator, owcft> bht;

        // Test with the equivalent of SHA-256("")
        bht::block_type block = {{0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
        bht bh;
        bh.update(block);
        bht::digest_type h = bh.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << h std::endl;
#endif

        const char *eh = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        BOOST_CHECK_EQUAL(eh, std::to_string(h).data());
    }

    BOOST_AUTO_TEST_CASE(shacal_accumulator) {
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, 160,
                                                  hash::detail::sha1_policy::iv_generator,
                                                  hash::davies_meyer_compressor<block::shacal1,
                                                                                state_adder> > construction_type;
        typedef hash::merkle_damgard_state_preprocessor<construction_type, hash::stream_endian::big_octet_big_bit, 8,
                                                        construction_type::word_bits * 2> sha1_octet_hash;
        typedef sha1_octet_hash::digest_type digest_type;

        // perl -e 'for ($x = 1000000000; $x--;) {print "a";}' | sha1sum
        sha1_octet_hash h;
        for (unsigned n = 1000000000; n--;) {
            h.update_one('a');
        }
        digest_type d = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        printf("%s\n", std::to_string(d).data());
#endif

        const char *ed = "d0f3e4f2f31c665abbd8f518e848d5cb80ca78f7";
        BOOST_CHECK_EQUAL(ed, std::to_string(d).data());
    }

    BOOST_AUTO_TEST_CASE(shacal2_512_encrypt1) {
        unsigned const SHA = 512;
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, SHA,
                                                  hash::detail::sha2_policy<SHA>::iv_generator,
                                                  hash::davies_meyer_compressor<block::shacal2<SHA>,
                                                                                state_adder> > construction_type;
        typedef hash::merkle_damgard_state_preprocessor<construction_type, hash::stream_endian::big_octet_big_bit, 8,
                                                        construction_type::word_bits * 2> sha512_octet_hash;
        typedef sha512_octet_hash::digest_type digest_type;


        sha512_octet_hash h;
        digest_type d = h.end_message();
        printf("%s\n", std::to_string(d).data());
        const char *ed = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                         "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        BOOST_CHECK(!strcmp(ed, std::to_string(d).data()));
    }

    BOOST_AUTO_TEST_CASE(shacal2_512_encrypt2) {
        unsigned const SHA = 512;
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, SHA,
                                                  hash::detail::sha2_policy<SHA>::iv_generator,
                                                  hash::davies_meyer_compressor<block::shacal2<SHA>,
                                                                                state_adder> > construction_type;
        typedef hash::merkle_damgard_state_preprocessor<construction_type, hash::stream_endian::big_octet_big_bit, 8,
                                                        construction_type::word_bits * 2> sha512_octet_hash;
        typedef sha512_octet_hash::digest_type digest_type;

        sha512_octet_hash h;
        h.update_one('a').update_one('b').update_one('c');
        digest_type d = h.end_message();
        printf("%s\n", std::to_string(d).data());
        const char *ed = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        BOOST_CHECK(!strcmp(ed, std::to_string(d).data()));
    }

    BOOST_AUTO_TEST_CASE(shacal2_512_encrypt3) {
        unsigned const SHA = 512;
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, SHA,
                                                  hash::detail::sha2_policy<SHA>::iv_generator,
                                                  hash::davies_meyer_compressor<block::shacal2<SHA>,
                                                                                state_adder> > construction_type;
        typedef hash::merkle_damgard_state_preprocessor<construction_type, hash::stream_endian::big_octet_big_bit, 8,
                                                        construction_type::word_bits * 2> sha512_octet_hash;
        typedef sha512_octet_hash::digest_type digest_type;
        sha512_octet_hash h;
        const char *m = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        for (const char *p = m; *p; ++p) {
            h.update_one(*p);
        }
        digest_type d = h.end_message();
        printf("%s\n", std::to_string(d).data());
        const char *ed = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                         "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
        BOOST_CHECK(!strcmp(ed, std::to_string(d).data()));
    }

    BOOST_AUTO_TEST_CASE(shacal2_512_accumulator1) {
        unsigned const SHA = 512;
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, SHA,
                                                  hash::detail::sha2_policy<SHA>::iv_generator,
                                                  hash::davies_meyer_compressor<block::shacal2<SHA>,
                                                                                state_adder> > construction_type;
        typedef hash::merkle_damgard_state_preprocessor<construction_type, hash::stream_endian::big_octet_big_bit, 8,
                                                        construction_type::word_bits * 2> sha512_octet_hash;
        typedef sha512_octet_hash::digest_type digest_type;

        sha512_octet_hash h;
        for (unsigned n = 1000000; n--;) {
            h.update_one('a');
        }
        digest_type d = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        printf("%s\n", std::to_string(d).data());
#endif

        const char *ed = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                         "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
        BOOST_CHECK_EQUAL(ed, std::to_string(d).data());
    }

    BOOST_AUTO_TEST_CASE(shacal2_512_accumulator2) {
        unsigned const SHA = 512;
        typedef hash::merkle_damgard_construction<hash::stream_endian::big_octet_big_bit, SHA,
                                                  hash::detail::sha2_policy<SHA>::iv_generator,
                                                  hash::davies_meyer_compressor<block::shacal2<SHA>,
                                                                                state_adder> > construction_type;
        typedef hash::merkle_damgard_state_preprocessor<construction_type, hash::stream_endian::big_octet_big_bit, 8,
                                                        construction_type::word_bits * 2> sha512_octet_hash;
        typedef sha512_octet_hash::digest_type digest_type;

        // perl -e 'for ($x = 1000000000; $x--;) {print "a";}' | sha512sum
        sha512_octet_hash h;
        for (unsigned n = 1000000000; n--;) {
            h.update_one('a');
        }
        digest_type d = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        printf("%s\n", std::to_string(d).data());
#endif

        const char *ed = "7cc86d7e06edc6a2029b8c0fa0e3ffb013888fd360f8faf681c7cffd08eacffb"
                         "f09ae159827fc6e4c03894e6ecf4616395d3479f80d66ed3ac81a64ea0445f32";
        BOOST_CHECK_EQUAL(ed, std::to_string(d).data());
    }

BOOST_AUTO_TEST_SUITE_END()
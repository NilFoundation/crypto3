//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sha2_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

using namespace nil::crypto3::hash;
using namespace nil::crypto3::accumulators;

template<std::size_t Size>
class fixture {
public:
    accumulator_set<sha2<Size>> acc;
    typedef sha2<Size> hash_t;

    virtual ~fixture() {
    }
};

BOOST_TEST_DONT_PRINT_LOG_VALUE(sha2<224>::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(sha2<256>::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(sha2<384>::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(sha2<512>::digest_type)

BOOST_AUTO_TEST_SUITE(sha2_test_suite)

//
// Appendix references are from
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
//

//
// Additional test vectors from
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
//


BOOST_AUTO_TEST_CASE(sha2_224_subbyte0) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

    // B.1/1
    std::array<bool, 50> a = {0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1};
    sha2<224>::digest_type d = hash<sha2<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("e3b048552c3c387bcab37f6eb06bb79b96a4aee5ff27f51531a9551c", std::to_string(d).data());
}
/*
BOOST_AUTO_TEST_CASE(sha2_224_subbyte) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

    // B.1/1
    std::array<char, 1> a = {'\x84'};        //0x68
    sha2<224>::digest_type d = hash<sha2<224>>(a);

    BOOST_CHECK_EQUAL("3cd36921df5d6963e73739cf4d20211e2d8877c19cff087ade9d0e3a", std::to_string(d).data());
}


BOOST_AUTO_TEST_CASE(sha2_224_subbyte1) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

    // B.1/1
    std::array<char, 10> a = {'\x00','\x64','\x70','\xd5','\x7d','\xad','\x98','\x93','\xdc','\x03'};
    sha2<224>::digest_type d = hash<sha2<224>>(a);

    BOOST_CHECK_EQUAL("c90026cda5ad24115059c62ae9add57793ade445d4742273288bbce7", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_224_subbyte2) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

    // B.1/1
    std::array<bool, 5> a = {0, 1, 1, 0, 1};
    sha2<224>::digest_type d = hash<sha2<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("e3b048552c3c387bcab37f6eb06bb79b96a4aee5ff27f51531a9551c", std::to_string(d).data());
}


BOOST_AUTO_TEST_CASE(sha2_224_subbyte3) {
    // From http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

    // B.1/1
    std::array<bool, 10> a = {0, 1, 0, 1, 0, 0, 0, 0, 0, 1};
    sha2<224>::digest_type d = hash<sha2<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("869944dc261b4affdcd429d00f0bc5c43f2fe545bef20a77980098cd", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_256_subbyte) {
    // C.1/1
    std::array<bool, 5> a = {0, 1, 1, 0, 1};
    sha2<256>::digest_type d = hash<sha2<256>>(a);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL("d6d3e02a31a84a8caa9718ed6c2057be09db45e7823eb5079ce7a573a3760f95", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_384_subbyte) {
    // D.1/1
    std::array<bool, 5> a = {0, 0, 0, 1, 0};
    sha2<384>::digest_type d = hash<sha2<384>>(a);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL(
        "8d17be79e32b6718e07d8a603eb84ba0478f7fcfd1bb93995f7d1149e09143ac1ffcfc56820e469f3878d957a15a3fe4",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha2_512_subbyte) {
    // E.1/1
    std::array<bool, 5> a = {1, 0, 1, 1, 0};
    sha2<512>::digest_type d = hash<sha2<512>>(a);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif
    BOOST_CHECK_EQUAL(
        "d4ee29a9e90985446b913cf1d1376c836f4be2c1cf3cada0720a6bf4857d886a7ecb3c4e4c0fa8c7f95214e41dc1b0d21b22a84cc03bf8"
        "ce4845f34dd5bdbad4",
        std::to_string(d).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_256_empty_accumulator, fixture<256>) {
    BOOST_CHECK_NO_THROW(hash_t::digest_type s = (extract::hash<hash_t>(acc)));

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif
}

BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator1, fixture<256>) {
    // 0-length input: echo -n | sha256sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0
    hash_t::construction::type::block_type m = {{0x80000000u}};
    acc(m);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", s);
}

BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator2, fixture<256>) {
    // Example from appendix B.1: echo -n "abc" | sha256sum
    hash_t::construction::type::block_type m = {{}};
    m[0] = 0x61626380;
    m[15] = 0x00000018;
    acc(m);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", s);
}

BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator3, fixture<256>) {
    // Example from appendix B.2:
    // echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha256sum
    hash_t::construction::type::block_type m1 = {
        {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d6e6f70, 0x6e6f7071, 0x80000000, 0x00000000}};
    acc(m1);

    BOOST_CHECK_EQUAL("85e655d6417a17953363376a624cde5c76e09589cac5f811cc4b32c1f20e533a", (extract::hash<hash_t>(acc)));

    hash_t::construction::type::block_type m2 = {{}};
    m2[15] = 0x000001c0;
    acc(m2);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", std::to_string(s).data());
}


BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator4, fixture<256>) {
    // Example from appendix B.2:
    // echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha256sum

    hash_t::construction::type::block_type m2 = {{}};
    m2[15] = 0x000001c0;
    acc(m2);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", std::to_string(s).data());
}


BOOST_FIXTURE_TEST_CASE(sha2_256_accumulator5, fixture<256>) {
    // Example from appendix B.2:
    // echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha256sum
    hash_t::construction::type::block_type m1 = {
        {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a, 0x68696a6b, 0x696a6b6c,
         0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d6e6f70, 0x6e6f7071, 0x80000000, 0x00000000}};
    acc(m1);

    acc(m1);    

    hash_t::construction::type::block_type m2 = {{}};
    m2[15] = 0x000001c0;
    acc(m2);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", std::to_string(s).data());
}



BOOST_FIXTURE_TEST_CASE(sha2_384_empty_accumulator, fixture<384>) {
    BOOST_CHECK_NO_THROW(hash_t::digest_type s = (extract::hash<hash_t>(acc)));

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif
}

BOOST_FIXTURE_TEST_CASE(sha2_384_accumulator1, fixture<384>) {
    // 0-length input: echo -n | sha256sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0
    hash_t::construction::type::block_type m = {{UINT64_C(0x8000000000000000)}};
    acc(m);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
        "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_384_accumulator2, fixture<384>) {
    // Example from appendix D.1: echo -n "abc" | sha384sum
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x6162638000000000);
    m[15] = UINT64_C(0x0000000000000018);

    acc(m);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_384_accumulator3, fixture<384>) {
    // Example from appendix D.2:
    // echo -n "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn (continues)
    //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" | sha384sum
    hash_t::construction::type::block_type m1 = {
        {UINT64_C(0x6162636465666768), UINT64_C(0x6263646566676869), UINT64_C(0x636465666768696a),
         UINT64_C(0x6465666768696a6b), UINT64_C(0x65666768696a6b6c), UINT64_C(0x666768696a6b6c6d),
         UINT64_C(0x6768696a6b6c6d6e), UINT64_C(0x68696a6b6c6d6e6f), UINT64_C(0x696a6b6c6d6e6f70),
         UINT64_C(0x6a6b6c6d6e6f7071), UINT64_C(0x6b6c6d6e6f707172), UINT64_C(0x6c6d6e6f70717273),
         UINT64_C(0x6d6e6f7071727374), UINT64_C(0x6e6f707172737475), UINT64_C(0x8000000000000000),
         UINT64_C(0x0000000000000000)}};
    acc(m1);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "2a7f1d895fd58e0beaae96d1a673c741015a2173796c1a88"
        "f6352ca156acaff7c662113e9ebb4d6417b61a85e2ccf0a9",
        std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {{}};
    m2[15] = 0x0000000000000380L;
    acc(m2);
    hash_t::digest_type s2 = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s2).data());
#endif

    BOOST_CHECK_EQUAL(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
        "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_512_empty_accumulator, fixture<512>) {
    BOOST_CHECK_NO_THROW(hash_t::digest_type s = (extract::hash<hash_t>(acc)));

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif
}

BOOST_FIXTURE_TEST_CASE(sha2_512_accumulator1, fixture<512>) {
    // 0-length input: echo -n | sha512sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0
    hash_t::construction::type::block_type m = {{UINT64_C(0x8000000000000000)}};
    acc(m);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_512_accumulator2, fixture<512>) {
    // Example from appendix C.1: echo -n "abc" | sha512sum
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x6162638000000000);
    m[15] = UINT64_C(0x0000000000000018);
    acc(m);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha2_512_accumulator3, fixture<512>) {
    // Example from appendix C.2:
    // echo -n "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn (continues)
    //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" | sha512sum
    hash_t::construction::type::block_type m1 = {{
        UINT64_C(0x6162636465666768),
        UINT64_C(0x6263646566676869),
        UINT64_C(0x636465666768696a),
        UINT64_C(0x6465666768696a6b),
        UINT64_C(0x65666768696a6b6c),
        UINT64_C(0x666768696a6b6c6d),
        UINT64_C(0x6768696a6b6c6d6e),
        UINT64_C(0x68696a6b6c6d6e6f),
        UINT64_C(0x696a6b6c6d6e6f70),
        UINT64_C(0x6a6b6c6d6e6f7071),
        UINT64_C(0x6b6c6d6e6f707172),
        UINT64_C(0x6c6d6e6f70717273),
        UINT64_C(0x6d6e6f7071727374),
        UINT64_C(0x6e6f707172737475),
        UINT64_C(0x8000000000000000),
        UINT64_C(0x0000000000000000),
    }};
    acc(m1);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "4319017a2b706e69cd4b05938bae5e890186bf199f30aa956ef8b71d2f810585"
        "d787d6764b20bda2a26014470973692000ec057f37d14b8e06add5b50e671c72",
        std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {{}};
    m2[15] = 0x0000000000000380L;

    acc(m2);

    hash_t::digest_type s2 = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s2).data());
#endif

    BOOST_CHECK_EQUAL(
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor1) {
    accumulator_set<sha2<256>> acc;
    sha2<256>::digest_type s = extract::hash<sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor2) {
    // Example from Appendix B.1
    accumulator_set<sha2<256>> acc;
    acc('a');
    acc('b');
    acc('c');

    sha2<256>::digest_type s = extract::hash<sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha256_preprocessor3) {

    // Example from Appendix B.3
    accumulator_set<sha2<256>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    sha2<256>::digest_type s = extract::hash<sha2<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha384_preprocessor1) {
    accumulator_set<sha2<384>> acc;
    sha2<384>::digest_type s = extract::hash<sha2<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
        "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha384_preprocessor2) {
    // Example from Appendix D.1
    accumulator_set<sha2<384>> acc;
    acc('a');
    acc('b');
    acc('c');
    sha2<384>::digest_type s = extract::hash<sha2<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha384_preprocessor3) {
    // Example from Appendix D.1
    // Example from Appendix D.3
    accumulator_set<sha2<384>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    sha2<384>::digest_type s = extract::hash<sha2<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
        "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha512_preprocessor1) {
    accumulator_set<sha2<512>> acc;
    sha2<512>::digest_type s = extract::hash<sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha512_preprocessor2) {
    // Example from Appendix C.1
    accumulator_set<sha2<512>> acc;
    acc('a');
    acc('b');
    acc('c');

    sha2<512>::digest_type s = extract::hash<sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha512_preprocessor3) {
    // Example from Appendix C.3
    accumulator_set<sha2<512>> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    sha2<512>::digest_type s = extract::hash<sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha224_range_hash) {
    sha2<224>::digest_type h = hash<sha2<224>>(std::string("abc"));
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif
    BOOST_CHECK_EQUAL("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", std::to_string(h).data());
}

BOOST_AUTO_TEST_CASE(sha224_iterator_range_hash) {
}

BOOST_AUTO_TEST_CASE(sha512_various_hash1) {
    accumulator_set<sha2<512>> acc;
    sha2<512>::stream_processor<accumulator_set<sha2<512>>, 16>::type pp(acc);
    for (unsigned i = 0; i < 1000000 / 2; ++i) {
        pp.update_one(('a' << 8) | 'a');
    }
    sha2<512>::digest_type h = extract::hash<sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        std::to_string(h).data());
}

BOOST_AUTO_TEST_CASE(sha512_various_hash2) {
    accumulator_set<sha2<512>> acc;
    sha2<512>::stream_processor<accumulator_set<sha2<512>>, 32>::type pp(acc);
    for (unsigned i = 0; i < 1000000 / 4; ++i) {
        pp.update_one(('a' << 24) | ('a' << 16) | ('a' << 8) | 'a');
    }
    sha2<512>::digest_type h = extract::hash<sha2<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        std::to_string(h).data());
}
*/
BOOST_AUTO_TEST_SUITE_END()
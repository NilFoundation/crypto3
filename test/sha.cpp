//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sha_test

//#define CRYPTO3_HASH_SHOW_PROGRESS
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/sha.hpp>
#include <nil/crypto3/hash/sha1.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <cassert>
#include <cstring>
#include <unordered_map>

#include <boost/cstdint.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#define B0 0, 0, 0, 0
#define B1 0, 0, 0, 1
#define B2 0, 0, 1, 0
#define B3 0, 0, 1, 1
#define B4 0, 1, 0, 0
#define B5 0, 1, 0, 1
#define B6 0, 1, 1, 0
#define B7 0, 1, 1, 1
#define B8 1, 0, 0, 0
#define B9 1, 0, 0, 1
#define BA 1, 0, 1, 0
#define BB 1, 0, 1, 1
#define BC 1, 1, 0, 0
#define BD 1, 1, 0, 1
#define BE 1, 1, 1, 0
#define BF 1, 1, 1, 1

using namespace nil::crypto3::hash;
using namespace nil::crypto3::accumulators;

class fixture {
public:
    sha1::construction::type a;
};

namespace std {
    template<>
    struct hash<std::pair<std::vector<std::uint32_t>, std::size_t>> {
        size_t operator()(const std::pair<std::vector<std::uint32_t>, std::size_t> &x) const {
            return std::accumulate(
                x.first.begin(), x.first.end(),
                std::hash<std::pair<std::vector<std::uint32_t>, std::size_t>::first_type::value_type>()(
                    *x.first.begin()),
                [&](std::size_t a, const std::vector<uint32_t>::value_type &c) {
                    return a ^ std::hash<std::vector<uint32_t>::value_type>()(c);
                });
            /* your code here, e.g. "return hash<int>()(x.value);" */
        }
    };

}    // namespace std

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<sha::digest_type> {
                void operator()(::std::ostream &os, sha::digest_type const &p) {
                }
            };

            template<template<typename, typename> class P, typename T, typename U>
            struct print_log_value<P<T, U>> {
                void operator()(::std::ostream &os, P<T, U> const &p) {
                }
            };

            template<template<typename, typename> class P, template<typename> class V, typename T, typename U>
            struct print_log_value<P<V<T>, U>> {
                void operator()(::std::ostream &os, P<V<T>, U> const &p) {
                }
            };

            template<template<typename, typename> class M, template<typename, typename> class P,
                     template<typename> class V, typename T, typename U, typename I>
            struct print_log_value<M<P<V<T>, I>, U>> {
                void operator()(::std::ostream &os, M<P<V<T>, I>, U> const &p) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

static const std::unordered_map<std::vector<bool>, std::pair<std::size_t, std::string>> bool_string_data = {
    {{1, 0, 0, 1, 1}, {5, "29826b003b906e660eff4027ce98af3531ac75ba"}},
    {{1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1,
      1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0,
      1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1,
      1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0},
     {128, "82abff6605dbe1c17def12a394fa22a82b544a35"}},
    {{B4, B9, BB, B2, BA, BE, BC, B2, B5, B9, B4, BB, BB, BE, B3, BA,
      B3, BB, B1, B1, B7, B5, B4, B2, BD, B9, B4, BA, BC, B8, B8},
     {123, "6239781e03729919c01955b3ffa8acb60b988340"}},
    {{B6, B5, BF, B9, B3, B2, B9, B9, B5, BB, BA, B4, BC, BE, B2, BC, BB, B1, BB, B4, BA, B2, BE, B7, B1, BA,
      BE, B7, B0, B2, B2, B0, BA, BA, BC, BE, BC, B8, B9, B6, B2, BD, BD, B4, B4, B9, B9, BC, BB, BD, B7, BC,
      B8, B8, B7, BA, B9, B4, BE, BA, BA, BA, B1, B0, B1, BE, BA, B5, BA, BA, BB, BC, B5, B2, B9, BB, B4, BE,
      B7, BE, B4, B3, B6, B6, B5, BA, B5, BA, BF, B2, BC, BD, B0, B3, BF, BE, B6, B7, B8, BE, BA, B6, BA, B5,
      B0, B0, B5, BB, BB, BA, B3, BB, B0, B8, B2, B2, B0, B4, BC, B2, B8, BB, B9, B1, B0, B9, BF, B4, B6, B9,
      BD, BA, BC, B9, B2, BA, BA, BA, BB, B3, BA, BA, B7, BC, B1, B1, BA, B1, BB, B3, B2, BA, BE},
     {611, "8c5b2a5ddae5a97fc7f9d85661c672adbf7933d4"}}};

static const std::unordered_map<std::pair<std::vector<std::uint32_t>, std::size_t>, std::string> integer_string_data = {
    {{{0x9a7dfdf1, 0xecead06e, 0xd646aa55, 0xfe757146}, 128}, "82abff6605dbe1c17def12a394fa22a82b544a35"},
    {{{0xf78f9214, 0x1bcd170a, 0xe89b4fba, 0x15a1d59f, 0x3fd84d22, 0x3c9251bd, 0xacbbae61, 0xd05ed115, 0xa06a7ce1,
       0x17b7beea, 0xd24421de, 0xd9c32592, 0xbd57edea, 0xe39c39fa, 0x1fe8946a, 0x84d0cf1f, 0x7beead17, 0x13e2e095,
       0x9897347f, 0x67c80b04, 0x00c20981, 0x5d6b10a6, 0x83836fd5, 0x562a56ca, 0xb1a28e81, 0xb6576654, 0x631cf165,
       0x66b86e3b, 0x33a108b0, 0x5307c00a, 0xff14a768, 0xed735060, 0x6a0f85e6, 0xa91d396f, 0x5b5cbe57, 0x7f9b3880,
       0x7c7d523d, 0x6d792f6e, 0xbc24a4ec, 0xf2b3a427, 0xcdbbfb00},
      1304},
     "cb0082c8f197d260991ba6a460e76e202bad27b3"}};

//
// Appendix references are from
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
//

//
// Additional test vectors from
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
//

BOOST_AUTO_TEST_SUITE(sha_test_suite)

BOOST_AUTO_TEST_CASE(sha_collision) {
    // Reported 2004-08-12 by Joux, Carribault, Lemuet, and Jalby
    typedef sha::construction::type::word_type word_type;
    constexpr const std::array<word_type, 64> fic1 = {
        0xa766a602, 0xb65cffe7, 0x73bcf258, 0x26b322b3, 0xd01b1a97, 0x2684ef53, 0x3e3b4b7f, 0x53fe3762, 0x24c08e47,
        0xe959b2bc, 0x3b519880, 0xb9286568, 0x247d110f, 0x70f5c5e2, 0xb4590ca3, 0xf55f52fe, 0xeffd4c8f, 0xe68de835,
        0x329e603c, 0xc51e7f02, 0x545410d1, 0x671d108d, 0xf5a4000d, 0xcf20a439, 0x4949d72c, 0xd14fbb03, 0x45cf3a29,
        0x5dcda89f, 0x998f8755, 0x2c9a58b1, 0xbdc38483, 0x5e477185, 0xf96e68be, 0xbb0025d2, 0xd2b69edf, 0x21724198,
        0xf688b41d, 0xeb9b4913, 0xfbe696b5, 0x457ab399, 0x21e1d759, 0x1f89de84, 0x57e8613c, 0x6c9e3b24, 0x2879d4d8,
        0x783b2d9c, 0xa9935ea5, 0x26a729c0, 0x6edfc501, 0x37e69330, 0xbe976012, 0xcc5dfe1c, 0x14c4c68b, 0xd1db3ecb,
        0x24438a59, 0xa09b5db4, 0x35563e0d, 0x8bdf572f, 0x77b53065, 0xcef31f32, 0xdc9dbaa0, 0x4146261e, 0x9994bd5c,
        0xd0758e3d

    };

    constexpr const std::array<word_type, 64> fic2 = {
        0xa766a602, 0xb65cffe7, 0x73bcf258, 0x26b322b1, 0xd01b1ad7, 0x2684ef51, 0xbe3b4b7f, 0xd3fe3762,
        0xa4c08e45, 0xe959b2fc, 0x3b519880, 0x39286528, 0xa47d110d, 0x70f5c5e0, 0x34590ce3, 0x755f52fc,
        0x6ffd4c8d, 0x668de875, 0x329e603e, 0x451e7f02, 0xd45410d1, 0xe71d108d, 0xf5a4000d, 0xcf20a439,
        0x4949d72c, 0xd14fbb01, 0x45cf3a69, 0x5dcda89d, 0x198f8755, 0xac9a58b1, 0x3dc38481, 0x5e4771c5,
        0x796e68fe, 0xbb0025d0, 0x52b69edd, 0xa17241d8, 0x7688b41f, 0x6b9b4911, 0x7be696f5, 0xc57ab399,
        0xa1e1d719, 0x9f89de86, 0x57e8613c, 0xec9e3b26, 0xa879d498, 0x783b2d9e, 0x29935ea7, 0xa6a72980,
        0x6edfc503, 0x37e69330, 0x3e976010, 0x4c5dfe5c, 0x14c4c689, 0x51db3ecb, 0xa4438a59, 0x209b5db4,
        0x35563e0d, 0x8bdf572f, 0x77b53065, 0xcef31f30, 0xdc9dbae0, 0x4146261c, 0x1994bd5c, 0x50758e3d};

    sha::digest_type h1 = hash<sha>(fic1);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    printf("%s\n", h1.cstring().data());
#endif

    sha::digest_type h2 = hash<sha>(fic2);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    printf("%s\n", h2.cstring().data());
#endif

    BOOST_CHECK_EQUAL(h1, h2);

    constexpr const char *expected_hash = "c9f160777d4086fe8095fba58b7e20c228a4006b";
    BOOST_CHECK_EQUAL(expected_hash, std::to_string(h1).data());
    BOOST_CHECK_EQUAL(expected_hash, std::to_string(h2).data());
}

BOOST_AUTO_TEST_CASE(sha1_subbbyte1) {
    accumulator_set<sha1> acc;
    sha1::stream_processor<accumulator_set<sha1>, 1>::type h(acc);
    sha1::digest_type d = h.end_message();
    BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha1_subbyte2) {
    // echo -n "abc" | sha1sum
    accumulator_set<sha1> acc;
    sha1::stream_processor<accumulator_set<sha1>, 4>::type h(acc);
    h.update_one(0x6).update_one(0x1).update_one(0x6).update_one(0x2).update_one(0x6).update_one(0x3);
    sha1::digest_type d = h.end_message();
    BOOST_CHECK_EQUAL("a9993e364706816aba3e25717850c26c9cd0d89d", std::to_string(d).data());
}

// More from http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

BOOST_DATA_TEST_CASE(sha1_range_hash1, boost::unit_test::data::make(bool_string_data), element) {
    sha1::digest_type out;

    std::vector<bool> input = element.first;
    input.resize(element.second.first);
    hash<sha1>(input, out.begin());

    BOOST_CHECK_EQUAL(std::to_string(out).data(), element.second.second);
}

BOOST_DATA_TEST_CASE(sha1_iterator_range_hash1, boost::unit_test::data::make(bool_string_data), element) {
    sha1::digest_type out;

    std::vector<bool> input = element.first;
    input.resize(element.second.first);

    hash<sha1>(input.begin(), input.end(), out.begin());

    BOOST_CHECK_EQUAL(std::to_string(out).data(), element.second.second);
}

BOOST_DATA_TEST_CASE(sha1_return_range_hash1, boost::unit_test::data::make(bool_string_data), element) {
    std::vector<bool> input = element.first;
    input.resize(element.second.first);

    sha1::digest_type out = hash<sha1>(input);

    BOOST_CHECK_EQUAL(std::to_string(out).data(), element.second.second);
}

BOOST_DATA_TEST_CASE(sha1_accumulator_hash, boost::unit_test::data::make(integer_string_data), array_element) {
    accumulator_set<sha1> acc;
    sha1::stream_processor<accumulator_set<sha1>, 4>::type h(acc);

    for (unsigned i = 0; i < array_element.first.second; i += 4) {
        h.update_one((array_element.first.first[i / 32] >> (32 - 4 - i % 32)) % 0x10);
    }

    sha1::digest_type d = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", d.cstring().data());
#endif

    BOOST_CHECK_EQUAL(std::to_string(d).data(), array_element.second);
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator_hash1, fixture) {
    BOOST_CHECK_NO_THROW(sha1::digest_type s = a.end_message());

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    a.reset();
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator_hash2, fixture) {
    // 0-length input: echo -n | sha1sum

    // A single 1 bit after the (empty) message,
    // then pad with 0s,
    // then add the length, which is also 0
    sha1::construction::type::block_type m = {{0x80000000u}};
    a.process_block(m);

    sha1::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", std::to_string(s).data());

    a.reset();
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator_hash3, fixture) {
    // Example from appendix A.1: echo -n "abc" | sha1sum
    sha1::construction::type::block_type m = {{}};
    m[0] = 0x61626380;
    m[15] = 0x00000018;
    a.process_block(m);

    sha1::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    BOOST_CHECK_EQUAL("a9993e364706816aba3e25717850c26c9cd0d89d", std::to_string(s).data());

    a.reset();
}

BOOST_FIXTURE_TEST_CASE(sha1_accumulator_hash4, fixture) {
    // Example from appendix A.2:
    // echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha1sum
    sha1::construction::type::block_type m1 = {{
        0x61626364,
        0x62636465,
        0x63646566,
        0x64656667,
        0x65666768,
        0x66676869,
        0x6768696a,
        0x68696a6b,
        0x696a6b6c,
        0x6a6b6c6d,
        0x6b6c6d6e,
        0x6c6d6e6f,
        0x6d6e6f70,
        0x6e6f7071,
        0x80000000,
        0x00000000,
    }};
    a.process_block(m1);

    BOOST_CHECK_EQUAL("f4286818c37b27ae0408f581846771484a566572", std::to_string(a.digest()).data());

    sha1::construction::type::block_type m2 = {{}};
    m2[15] = 0x000001c0;
    a.process_block(m2);

    sha1::digest_type s = a.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    BOOST_CHECK_EQUAL("84983e441c3bd26ebaae4aa1f95129e5e54670f1", std::to_string(s).data());

    a.reset();
}

BOOST_AUTO_TEST_CASE(sha1_preprocessor1) {
    accumulator_set<sha1> acc;
    sha1::stream_processor<accumulator_set<sha1>, 8>::type h(acc);
    sha1::digest_type s = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    BOOST_CHECK_EQUAL("da39a3ee5e6b4b0d3255bfef95601890afd80709", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha1_preprocessor2) {
    // Example from Appendix A.1
    accumulator_set<sha1> acc;
    sha1::stream_processor<accumulator_set<sha1>, 8>::type h(acc);
    h.update_one('a').update_one('b').update_one('c');
    sha1::digest_type s = h.end_message();

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    BOOST_CHECK_EQUAL("a9993e364706816aba3e25717850c26c9cd0d89d", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha1_preprocessor3) {
    // Example from Appendix A.3
    accumulator_set<sha1> acc;
    for (unsigned i = 0; i < 1000000; ++i) {
        acc('a');
    }
    sha1::digest_type s = extract::hash<sha1>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", s.cstring().data());
#endif

    BOOST_CHECK_EQUAL("34aa973cd4c4daa4f61eeb2bdbad27316534016f", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha1_various) {
    sha1::digest_type h = hash<sha1>(std::array<uint8_t, 1> {1});

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", h.cstring().data());
#endif
    BOOST_CHECK_EQUAL("bf8b4530d8d246dd74ac53a13471bba17941dff7", std::to_string(h).data());
}

BOOST_AUTO_TEST_CASE(sha0_various) {
    sha1::digest_type h = hash<sha0>(std::string("abc"));

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", h.cstring().data());
#endif

    BOOST_CHECK_EQUAL("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", std::to_string(h).data());
}

BOOST_AUTO_TEST_SUITE_END()

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE hash_pack_test

#include <boost/array.hpp>
#include <boost/cstdint.hpp>

#include <nil/crypto3/detail/pack.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <cstdio>

using namespace nil::crypto3;
using namespace nil::crypto3::detail;
using namespace nil::crypto3::stream_endian;


BOOST_AUTO_TEST_SUITE(pack_imploder_test_suite)

BOOST_AUTO_TEST_CASE(bubb_to_bubb) {
    std::array<uint8_t, 4> in = {{0x12, 0x34, 0x56, 0x78}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0x1234, 0x5678}};

    pack<big_octet_big_bit, big_octet_big_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bubb_to_bulb) {
    std::array<uint8_t, 4> in = {{0x12, 0x34, 0x56, 0x78}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0x482c6a1e}}; 

    pack<big_octet_big_bit, big_octet_little_bit, 8, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bubb_to_lubb) {
    std::array<uint8_t, 8> in = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0xefcdab9078563412}};

    pack<big_octet_big_bit, little_octet_big_bit, 8, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);    
}

BOOST_AUTO_TEST_CASE(bubb_to_lulb) {
    std::array<uint16_t, 2> in = {{0x1234, 0x5678}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0x1e6a2c48}};

    pack<big_octet_big_bit, little_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_bubb) {
    std::array<uint16_t, 4> in = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0x34127856ab90efcd}};

    pack<little_octet_big_bit, big_octet_big_bit, 16, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_bulb) {
    std::array<uint32_t, 2> in = {{0x12345678, 0x90abcdef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0x1e6a2c48f7b3d509}};

    pack<little_octet_big_bit, big_octet_little_bit, 32, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb) {
    std::array<uint8_t, 2> in = {{0x56, 0x78}};
    std::array<uint16_t, 1> out {};
    std::array<uint16_t, 1> res = {{0x7856}};

    pack<little_octet_big_bit, little_octet_big_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_lulb) {
    std::array<uint8_t, 8> in = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x1e6a2c48, 0xf7b3d509}};

    pack<little_octet_big_bit, little_octet_little_bit, 8, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bubb) {
    std::array<uint8_t, 16> in = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 
                                   0x48, 0x2c, 0x6a, 0x1e, 0x09, 0xd5, 0xb3, 0xf7}};
    std::array<uint64_t, 2> out {};
    std::array<uint64_t, 2> res = {{0x482c6a1e09d5b3f7, 0x1234567890abcdef}};

    pack<big_octet_little_bit, big_octet_big_bit, 8, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bulb) {
    std::array<uint16_t, 4> in = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x12345678, 0x90abcdef}};

    pack<big_octet_little_bit, big_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lubb) {
    std::array<uint16_t, 8> in = {{0x1234, 0x5678, 0x90ab, 0xcdef, 0x482c, 0x6a1e, 0x09d5, 0xb3f7}};
    std::array<uint64_t, 2> out {};
    std::array<uint64_t, 2> res = {{0xf7b3d5091e6a2c48, 0xefcdab9078563412}};

    pack<big_octet_little_bit, little_octet_big_bit, 16, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lulb) {
    std::array<uint32_t, 4> in = {{0x12345678, 0x90abcdef, 0x482c6a1e, 0x09d5b3f7}};
    std::array<uint64_t, 2> out {};
    std::array<uint64_t, 2> res = {{0xefcdab9078563412, 0xf7b3d5091e6a2c48}};

    pack<big_octet_little_bit, little_octet_little_bit, 32, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bubb) {
    std::array<uint8_t, 4> in = {{0x48, 0x2c, 0x6a, 0x1e}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0x1234, 0x5678}};

    pack<little_octet_little_bit, big_octet_big_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bulb) {
    std::array<uint16_t, 2> in = {{0x09d5, 0xb3f7}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0xd509f7b3}};

    pack<little_octet_little_bit, big_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lubb) {
    std::array<uint16_t, 4> in = {{0x482c, 0x6a1e, 0x09d5, 0xb3f7}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0xcdef90ab56781234}};

    pack<little_octet_little_bit, little_octet_big_bit, 16, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lulb) {
    std::array<uint32_t, 4> in = {{0x12345678, 0x90abcdef, 0x482c6a1e, 0x09d5b3f7}};
    std::array<uint64_t, 2> out {};
    std::array<uint64_t, 2> res = {{0x90abcdef12345678, 0x09d5b3f7482c6a1e}};

    pack<little_octet_little_bit, little_octet_little_bit, 32, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(pack_exploder_test_suite)

BOOST_AUTO_TEST_CASE(bubb_to_bubb) {
    std::array<uint16_t, 2> in = {{0x1234, 0x5678}};
    std::array<uint8_t, 4> out {};
    std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}};

    pack<big_octet_big_bit, big_octet_big_bit, 16, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bubb_to_bulb) {
    std::array<uint32_t, 1> in = {{0x482c6a1e}};
    std::array<uint8_t, 4> out {};
    std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}}; 

    pack<big_octet_big_bit, big_octet_little_bit, 32, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bubb_to_lubb) {
    std::array<uint64_t, 1> in = {{0xefcdab9078563412}};
    std::array<uint8_t, 8> out {};
    std::array<uint8_t, 8> res = {{0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12}};

    pack<big_octet_big_bit, little_octet_big_bit, 64, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);    
}

BOOST_AUTO_TEST_CASE(bubb_to_lulb) {
    std::array<uint32_t, 1> in = {{0x1e6a2c48}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0x5678, 0x1234}};

    pack<big_octet_big_bit, little_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_bubb) {
    std::array<uint64_t, 1> in = {{0x34127856ab90efcd}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0xcdef, 0x90ab, 0x5678, 0x1234}};

    pack<little_octet_big_bit, big_octet_big_bit, 64, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_bulb) {
    std::array<uint64_t, 1> in = {{0x1e6a2c48f7b3d509}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x90abcdef, 0x12345678}};

    pack<little_octet_big_bit, big_octet_little_bit, 64, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb) {
    std::array<uint16_t, 1> in = {{0x7856}};
    std::array<uint8_t, 2> out {};
    std::array<uint8_t, 2> res = {{0x56, 0x78}};

    pack<little_octet_big_bit, little_octet_big_bit, 16, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_lulb) {
    std::array<uint32_t, 2> in = {{0x1e6a2c48, 0xf7b3d509}};
    std::array<uint8_t, 8> out {};
    std::array<uint8_t, 8> res = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}};

    pack<little_octet_big_bit, little_octet_little_bit, 32, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bubb) {
    std::array<uint64_t, 2> in = {{0x482c6a1e09d5b3f7, 0x1234567890abcdef}}; 
    std::array<uint8_t, 16> out {};
    std::array<uint8_t, 16> res = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 
                                    0x48, 0x2c, 0x6a, 0x1e, 0x09, 0xd5, 0xb3, 0xf7}};

    pack<big_octet_little_bit, big_octet_big_bit, 64, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bulb) {
    std::array<uint32_t, 2> in = {{0x12345678, 0x90abcdef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

    pack<big_octet_little_bit, big_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lubb) {
    std::array<uint64_t, 2> in = {{0xf7b3d5091e6a2c48, 0xefcdab9078563412}};
    std::array<uint16_t, 8> out {};
    std::array<uint16_t, 8> res = {{0xcdef, 0x90ab, 0x5678, 0x1234, 0xb3f7, 0x09d5, 0x6a1e, 0x482c}};

    pack<big_octet_little_bit, little_octet_big_bit, 64, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lulb) {
    std::array<uint64_t, 2> in = {{0xefcdab9078563412, 0xf7b3d5091e6a2c48}};
    std::array<uint32_t, 4> out {};
    std::array<uint32_t, 4> res = {{0x90abcdef, 0x12345678, 0x09d5b3f7, 0x482c6a1e}};

    pack<big_octet_little_bit, little_octet_little_bit, 64, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bubb) {
    std::array<uint16_t, 2> in = {{0x1234, 0x5678}};
    std::array<uint8_t, 4> out {};
    std::array<uint8_t, 4> res = {{0x2c, 0x48, 0x1e, 0x6a}};

    pack<little_octet_little_bit, big_octet_big_bit, 16, 8>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bulb) {
    std::array<uint32_t, 1> in = {{0xd509f7b3}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0xb3f7, 0x09d5}};

    pack<little_octet_little_bit, big_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lubb) {
    std::array<uint64_t, 1> in = {{0xcdef90ab56781234}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x482c, 0x6a1e, 0x09d5, 0xb3f7}};

    pack<little_octet_little_bit, little_octet_big_bit, 64, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lulb) {
    std::array<uint64_t, 2> in = {{0x90abcdef12345678, 0x09d5b3f7482c6a1e}};
    std::array<uint32_t, 4> out {};
    std::array<uint32_t, 4> res = {{0x12345678, 0x90abcdef, 0x482c6a1e, 0x09d5b3f7}};

    pack<little_octet_little_bit, little_octet_little_bit, 64, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_SUITE_END()

/*
BOOST_AUTO_TEST_SUITE(pack_equal_test_suite)

BOOST_AUTO_TEST_SUITE_END()*/
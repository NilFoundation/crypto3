//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE hash_pack_test

#include <boost/array.hpp>
#include <boost/cstdint.hpp>

#include <nil/crypto3/hash/detail/pack.hpp>

#include <nil/crypto3/hash/hash_state.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <sstream>
#include <iterator>

#include <cassert>
#include <cstdio>

using boost::int8_t;
using boost::int16_t;
using boost::int32_t;

using namespace nil::crypto3::hash;
using namespace nil::crypto3::hash::stream_endian;

BOOST_AUTO_TEST_SUITE(hash_pack_test_suite)

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_big_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb2) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint8_t, 8> out{};
        pack<big_octet_big_bit, 32, 8>(in, out);
        std::array<uint8_t, 8> eout = {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb3) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint16_t, 4> out{};
        pack<big_octet_big_bit, 32, 16>(in, out);
        std::array<uint16_t, 4> eout = {{0x0123, 0x4567, 0x89AB, 0xCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb4) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 4> out{};
        pack<big_octet_big_bit, 16, 8>(in, out);
        std::array<uint8_t, 4> eout = {{0x45, 0x67, 0x89, 0xAB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb5) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 8> out{};
        pack<big_octet_big_bit, 16, 4>(in, out);
        std::array<uint8_t, 8> eout = {{0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb6) {
        std::array<uint16_t, 1> in = {{0xEC15}};
        std::array<bool, 16> out{};
        pack<big_octet_big_bit, 16, 1>(in, out);
        std::array<bool,
                16> eout = {{true, true, true, false, true, true, false, false, false, false, false, true, false, true, false, true}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb7) {
        std::array<uint8_t, 2> in = {{0xC, 0x5}};
        std::array<bool, 8> out{};
        pack<big_octet_big_bit, 4, 1>(in, out);
        std::array<bool, 8> eout = {{true, true, false, false, false, true, false, true}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebb8) {
        std::array<uint16_t, 1> in = {{(31 << 10) | (17 << 5) | (4 << 0)}};
        std::array<uint8_t, 3> out{};
        pack<big_bit, 15, 5>(in, out);
        std::array<uint8_t, 3> eout = {{31, 17, 4}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_big_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb2) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint8_t, 8> out{};
        pack<little_octet_big_bit, 32, 8>(in, out);
        std::array<uint8_t, 8> eout = {{0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb3) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint16_t, 4> out{};
        pack<little_octet_big_bit, 32, 16>(in, out);
        std::array<uint16_t, 4> eout = {{0x4567, 0x0123, 0xCDEF, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb4) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 4> out{};
        pack<little_octet_big_bit, 16, 8>(in, out);
        std::array<uint8_t, 4> eout = {{0x67, 0x45, 0xAB, 0x89}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb5) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 8> out{};
        pack<little_octet_big_bit, 16, 4>(in, out);
        std::array<uint8_t, 8> eout = {{0x6, 0x7, 0x4, 0x5, 0xA, 0xB, 0x8, 0x9}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb6) {
        std::array<uint16_t, 1> in = {{0xEC15}};
        std::array<bool, 16> out{};
        pack<little_octet_big_bit, 16, 1>(in, out);
        std::array<bool,
                16> eout = {{false, false, false, true, false, true, false, true, true, true, true, false, true, true, false, false}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb7) {
        std::array<uint16_t, 1> in = {{0xEC15}};
        std::array<bool, 16> out{};
        pack<little_octet_big_bit, 16, 1>(in, out);
        std::array<bool,
                16> eout = {{false, false, false, true, false, true, false, true, true, true, true, false, true, true, false, false}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodelb8) {
        std::array<uint8_t, 2> in = {{0xC, 0x5}};
        std::array<bool, 8> out{};
        pack<little_octet_big_bit, 4, 1>(in, out);
        std::array<bool, 8> eout = {{true, true, false, false, false, true, false, true}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_little_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl2) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint8_t, 8> out{};
        pack<big_octet_little_bit, 32, 8>(in, out);
        std::array<uint8_t, 8> eout = {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl3) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint16_t, 4> out{};
        pack<big_octet_little_bit, 32, 16>(in, out);
        std::array<uint16_t, 4> eout = {{0x0123, 0x4567, 0x89AB, 0xCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl4) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 4> out{};
        pack<big_octet_little_bit, 16, 8>(in, out);
        std::array<uint8_t, 4> eout = {{0x45, 0x67, 0x89, 0xAB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl5) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 8> out{};
        pack<big_octet_little_bit, 16, 4>(in, out);
        std::array<uint8_t, 8> eout = {{0x5, 0x4, 0x7, 0x6, 0x9, 0x8, 0xB, 0xA}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl6) {
        std::array<uint16_t, 1> in = {{0xEC15}};
        std::array<bool, 16> out{};
        pack<big_octet_little_bit, 16, 1>(in, out);
        std::array<bool,
                16> eout = {{false, false, true, true, false, true, true, true, true, false, true, false, true, false, false, false}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodebl7) {
        std::array<uint8_t, 2> in = {{0xC, 0x5}};
        std::array<bool, 8> out{};
        pack<big_octet_little_bit, 4, 1>(in, out);
        std::array<bool, 8> eout = {{false, false, true, true, true, false, true, false}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_little_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell2) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint8_t, 8> out{};
        pack<little_octet_little_bit, 32, 8>(in, out);
        std::array<uint8_t, 8> eout = {{0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell3) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint16_t, 4> out{};
        pack<little_octet_little_bit, 32, 16>(in, out);
        std::array<uint16_t, 4> eout = {{0x4567, 0x0123, 0xCDEF, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell4) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 4> out{};
        pack<little_octet_little_bit, 16, 8>(in, out);
        std::array<uint8_t, 4> eout = {{0x67, 0x45, 0xAB, 0x89}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell5) {
        std::array<uint16_t, 2> in = {{0x4567, 0x89AB}};
        std::array<uint8_t, 8> out{};
        pack<little_octet_little_bit, 16, 4>(in, out);
        std::array<uint8_t, 8> eout = {{0x7, 0x6, 0x5, 0x4, 0xB, 0xA, 0x9, 0x8}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell6) {
        std::array<uint16_t, 1> in = {{0xEC15}};
        std::array<bool, 16> out{};
        pack<little_octet_little_bit, 16, 1>(in, out);
        std::array<bool,
                16> eout = {{true, false, true, false, true, false, false, false, false, false, true, true, false, true, true, true}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell7) {
        std::array<uint8_t, 2> in = {{0xC, 0x5}};
        std::array<bool, 8> out{};
        pack<little_octet_little_bit, 4, 1>(in, out);
        std::array<bool, 8> eout = {{false, false, true, true, true, false, true, false}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_explodell8) {
        std::array<uint16_t, 1> in = {{(31 << 10) | (17 << 5) | (4 << 0)}};
        std::array<uint8_t, 3> out{};
        pack<little_bit, 15, 5>(in, out);
        std::array<uint8_t, 3> eout = {{4, 17, 31}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_big_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb2) {
        std::array<uint8_t, 8> in = {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_big_bit, 8, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb3) {
        std::array<uint16_t, 4> in = {{0x0123, 0x4567, 0x89AB, 0xCDEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_big_bit, 16, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb4) {
        std::array<uint8_t, 4> in = {{0x45, 0x67, 0x89, 0xAB}};
        std::array<uint16_t, 2> out{};
        pack<big_octet_big_bit, 8, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb5) {
        std::array<uint8_t, 8> in = {{0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB}};
        std::array<uint16_t, 2> out{};
        pack<big_octet_big_bit, 4, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb6) {
        std::array<bool,
                16> in = {{true, true, true, false, true, true, false, false, false, false, false, true, false, true, false, true}};
        std::array<uint16_t, 1> out{};
        pack<big_octet_big_bit, 1, 16>(in, out);
        std::array<uint16_t, 1> eout = {{0xEC15}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb7) {
        std::array<bool, 8> in = {{true, true, false, false, false, true, false, true}};
        std::array<uint8_t, 2> out{};
        pack<big_octet_big_bit, 1, 4>(in, out);
        std::array<uint8_t, 2> eout = {{0xC, 0x5}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebb8) {
        std::array<uint8_t, 3> in = {{31, 17, 4}};
        std::array<uint16_t, 1> out{};
        pack<big_bit, 5, 15>(in, out);
        std::array<uint16_t, 1> eout = {{(31 << 10) | (17 << 5) | (4 << 0)}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_big_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb2) {
        std::array<uint8_t, 8> in = {{0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_big_bit, 8, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb3) {
        std::array<uint16_t, 4> in = {{0x4567, 0x0123, 0xCDEF, 0x89AB}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_big_bit, 16, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb4) {
        std::array<uint8_t, 4> in = {{0x67, 0x45, 0xAB, 0x89}};
        std::array<uint16_t, 2> out{};
        pack<little_octet_big_bit, 8, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb5) {
        std::array<uint8_t, 8> in = {{0x6, 0x7, 0x4, 0x5, 0xA, 0xB, 0x8, 0x9}};
        std::array<uint16_t, 2> out{};
        pack<little_octet_big_bit, 4, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb6) {
        std::array<bool,
                16> in = {{false, false, false, true, false, true, false, true, true, true, true, false, true, true, false, false}};
        std::array<uint16_t, 1> out{};
        pack<little_octet_big_bit, 1, 16>(in, out);
        std::array<uint16_t, 1> eout = {{0xEC15}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodelb7) {
        std::array<bool, 8> in = {{true, true, false, false, false, true, false, true}};
        std::array<uint8_t, 2> out{};
        pack<little_octet_big_bit, 1, 4>(in, out);
        std::array<uint8_t, 2> eout = {{0xC, 0x5}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_little_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl2) {
        std::array<uint8_t, 8> in = {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_little_bit, 8, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl3) {
        std::array<uint16_t, 4> in = {{0x0123, 0x4567, 0x89AB, 0xCDEF}};
        std::array<uint32_t, 2> out{};
        pack<big_octet_little_bit, 16, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl4) {
        std::array<uint8_t, 4> in = {{0x45, 0x67, 0x89, 0xAB}};
        std::array<uint16_t, 2> out{};
        pack<big_octet_little_bit, 8, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl5) {
        std::array<uint8_t, 8> in = {{0x5, 0x4, 0x7, 0x6, 0x9, 0x8, 0xB, 0xA}};
        std::array<uint16_t, 2> out{};
        pack<big_octet_little_bit, 4, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl6) {
        std::array<bool,
                16> in = {{false, false, true, true, false, true, true, true, true, false, true, false, true, false, false, false}};
        std::array<uint16_t, 1> out{};
        pack<big_octet_little_bit, 1, 16>(in, out);
        std::array<uint16_t, 1> eout = {{0xEC15}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodebl7) {
        std::array<bool, 8> in = {{false, false, true, true, true, false, true, false}};
        std::array<uint8_t, 2> out{};
        pack<big_octet_little_bit, 1, 4>(in, out);
        std::array<uint8_t, 2> eout = {{0xC, 0x5}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell1) {
        std::array<uint32_t, 2> in = {{0x01234567, 0x89ABCDEF}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_little_bit, 32, 32>(in, out);
        BOOST_CHECK(in == out);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell2) {
        std::array<uint8_t, 8> in = {{0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_little_bit, 8, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell3) {
        std::array<uint16_t, 4> in = {{0x4567, 0x0123, 0xCDEF, 0x89AB}};
        std::array<uint32_t, 2> out{};
        pack<little_octet_little_bit, 16, 32>(in, out);
        std::array<uint32_t, 2> eout = {{0x01234567, 0x89ABCDEF}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell4) {
        std::array<uint8_t, 4> in = {{0x67, 0x45, 0xAB, 0x89}};
        std::array<uint16_t, 2> out{};
        pack<little_octet_little_bit, 8, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell5) {
        std::array<uint8_t, 8> in = {{0x7, 0x6, 0x5, 0x4, 0xB, 0xA, 0x9, 0x8}};
        std::array<uint16_t, 2> out{};
        pack<little_octet_little_bit, 4, 16>(in, out);
        std::array<uint16_t, 2> eout = {{0x4567, 0x89AB}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell6) {
        std::array<bool,
                16> in = {{true, false, true, false, true, false, false, false, false, false, true, true, false, true, true, true}};
        std::array<uint16_t, 1> out{};
        pack<little_octet_little_bit, 1, 16>(in, out);
        std::array<uint16_t, 1> eout = {{0xEC15}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell7) {
        std::array<bool, 8> in = {{false, false, true, true, true, false, true, false}};
        std::array<uint8_t, 2> out{};
        pack<little_octet_little_bit, 1, 4>(in, out);
        std::array<uint8_t, 2> eout = {{0xC, 0x5}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_implodell8) {
        std::array<uint8_t, 3> in = {{4, 17, 31}};
        std::array<uint16_t, 1> out{};
        pack<little_bit, 5, 15>(in, out);
        std::array<uint16_t, 1> eout = {{(31 << 10) | (17 << 5) | (4 << 0)}};
        BOOST_CHECK(out == eout);
    }

    BOOST_AUTO_TEST_CASE(hash_pack_various1) {
        using namespace std;
        istringstream iss("-1 -2 -4 -8");
        ostringstream oss;
        pack<big_bit, 4, 16>(istream_iterator<int>(iss), istream_iterator<int>(), ostream_iterator<int>(oss, " "));
        BOOST_CHECK(oss.str() == "65224 ");
    }

    BOOST_AUTO_TEST_CASE(hash_pack_various2) {
        using namespace std;
        istringstream iss("-1 -2 -4 -8");
        ostringstream oss;
        pack<little_bit, 4, 16>(istream_iterator<int>(iss), istream_iterator<int>(), ostream_iterator<int>(oss, " "));
        BOOST_CHECK(oss.str() == "36079 ");
    }

    BOOST_AUTO_TEST_CASE(hash_pack_various3) {
        using namespace std;
        istringstream iss("-312");
        ostringstream oss;
        pack<big_bit, 16, 4>(istream_iterator<int>(iss), istream_iterator<int>(), ostream_iterator<int>(oss, " "));
        BOOST_CHECK(oss.str() == "15 14 12 8 ");
    }

    BOOST_AUTO_TEST_CASE(hash_pack_various4) {
        using namespace std;
        istringstream iss("-29457");
        ostringstream oss;
        pack<little_bit, 16, 4>(istream_iterator<int>(iss), istream_iterator<int>(), ostream_iterator<int>(oss, " "));
        BOOST_CHECK(oss.str() == "15 14 12 8 ");
    }

BOOST_AUTO_TEST_SUITE_END()
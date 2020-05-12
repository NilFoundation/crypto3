//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE hash_new_pack_test

#include <boost/array.hpp>
#include <boost/cstdint.hpp>

#include <nil/crypto3/detail/new_pack.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iterator>
#include <cstdio>

using namespace nil::crypto3;
using namespace nil::crypto3::detail;
using namespace nil::crypto3::stream_endian;


BOOST_AUTO_TEST_SUITE(pack_test_suite)

BOOST_AUTO_TEST_CASE(single_big_endian_equal1) {

    std::array<uint32_t, 2> in = {{0x01928374, 0x65473829}};
    std::array<uint32_t, 2> out {};

    packer<big_octet_big_bit, big_octet_big_bit, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_big_endian_equal2) {

    std::array<uint8_t, 2> in = {{0x01, 0x23}};
    std::array<uint8_t, 2> out {};

    packer<big_octet_big_bit, big_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_big_endian_equal3) {

    std::array<uint8_t, 2> in = {{0xC, 0x4}};
    std::array<uint8_t, 2> out {};

    packer<big_octet_big_bit, big_octet_big_bit, 4, 4>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_little_endian_equal1) {

    std::array<uint32_t, 2> in = {{0x01928374, 0x65473829}};
    std::array<uint32_t, 2> out {};

    packer<little_octet_big_bit, little_octet_big_bit, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_little_endian_equal2) {

    std::array<uint8_t, 2> in = {{0x01, 0x23}};
    std::array<uint8_t, 2> out {};

    packer<little_octet_big_bit, little_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_little_endian_equal3) {

    std::array<uint8_t, 2> in = {{0xC, 0x4}};
    std::array<uint8_t, 2> out {};

    packer<little_octet_big_bit, little_octet_big_bit, 4, 4>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(big_to_little_equal) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint8_t, 4> out {};

    packer<big_octet_big_bit, little_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(little_to_big_equal) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint8_t, 4> out {};

    packer<little_octet_big_bit, big_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(big_to_big_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0x89ad, 0x56ef}};

    packer<big_octet_big_bit, big_octet_big_bit, 8, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_little_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0xad89, 0xef56}};

    packer<little_octet_big_bit, little_octet_big_bit, 8, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_little_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0xef56ad89}};

    packer<big_octet_big_bit, little_octet_big_bit, 8, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_big_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0x89ad56ef}};

    packer<little_octet_big_bit, big_octet_big_bit, 8, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}


BOOST_AUTO_TEST_SUITE_END()
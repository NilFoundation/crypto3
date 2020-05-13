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

    new_packer<big_octet_big_bit, big_octet_big_bit, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_big_endian_equal2) {

    std::array<uint8_t, 2> in = {{0x01, 0x23}};
    std::array<uint8_t, 2> out {};

    new_packer<big_octet_big_bit, big_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_big_endian_equal3) {

    std::array<uint8_t, 2> in = {{0xC, 0x4}};
    std::array<uint8_t, 2> out {};

    new_packer<big_octet_big_bit, big_octet_big_bit, 4, 4>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_little_endian_equal1) {

    std::array<uint32_t, 2> in = {{0x01928374, 0x65473829}};
    std::array<uint32_t, 2> out {};

    new_packer<little_octet_big_bit, little_octet_big_bit, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_little_endian_equal2) {

    std::array<uint8_t, 2> in = {{0x01, 0x23}};
    std::array<uint8_t, 2> out {};

    new_packer<little_octet_big_bit, little_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(single_little_endian_equal3) {

    std::array<uint8_t, 2> in = {{0xC, 0x4}};
    std::array<uint8_t, 2> out {};

    new_packer<little_octet_big_bit, little_octet_big_bit, 4, 4>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(big_to_little_octet_equal) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint8_t, 4> out {};

    new_packer<big_octet_big_bit, little_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(little_to_big_octet_equal) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint8_t, 4> out {};

    new_packer<little_octet_big_bit, big_octet_big_bit, 8, 8>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(big_to_little_bit_equal) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint8_t, 4> out {};

    new_packer<big_octet_big_bit, little_octet_big_bit, 4, 4>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(little_to_big_bit_equal) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint8_t, 4> out {};

    new_packer<little_octet_big_bit, big_octet_big_bit, 4, 4>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == in);
}

BOOST_AUTO_TEST_CASE(big_to_little_equal) {

    std::array<uint16_t, 4> in = {{0x89ad, 0x56ef, 0x7340, 0x12cb}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0xad89, 0xef56, 0x4073, 0xcb12}};

    new_packer<big_octet_big_bit, little_octet_big_bit, 16, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_big_equal) {

    std::array<uint32_t, 2> in = {{0x89ad56ef, 0x734012cb}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0xef56ad89, 0xcb124073}};

    new_packer<little_octet_big_bit, big_octet_big_bit, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_big_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0x89ad, 0x56ef}};

    new_packer<big_octet_big_bit, big_octet_big_bit, 8, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_little_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0xad89, 0xef56}};

    new_packer<little_octet_big_bit, little_octet_big_bit, 8, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_little_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0xef56ad89}};

    new_packer<big_octet_big_bit, little_octet_big_bit, 8, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_big_octet_implode) {

    std::array<uint8_t, 4> in = {{0x89, 0xad, 0x56, 0xef}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0x89ad56ef}};

    new_packer<little_octet_big_bit, big_octet_big_bit, 8, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_big_implode) {

    std::array<uint16_t, 2> in = {{0x89ad, 0x56ef}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0x89ad56ef}};

    new_packer<big_octet_big_bit, big_octet_big_bit, 16, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_little_implode) {

    std::array<uint16_t, 2> in = {{0x89ad, 0x56ef}};
    std::array<uint32_t, 1> out {};
    std::array<uint32_t, 1> res = {{0x56ef89ad}};

    new_packer<little_octet_big_bit, little_octet_big_bit, 16, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_little_implode) {

    std::array<uint16_t, 4> in = {{0xab90, 0xcd34, 0x7812, 0x56ef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0xef56127834cd90ab}};

    new_packer<big_octet_big_bit, little_octet_big_bit, 16, 64>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_big_implode) {

    std::array<uint16_t, 4> in = {{0xab90, 0xcd34, 0x7812, 0x56ef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0x90ab34cd1278ef56}};

    new_packer<little_octet_big_bit, big_octet_big_bit, 16, 64>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_big_explode) {

    std::array<uint32_t, 1> in = {{0x89ad56ef}};
    std::array<uint16_t, 2> out {};
    std::array<uint16_t, 2> res = {{0x89ad, 0x56ef}};

    new_packer<big_octet_big_bit, big_octet_big_bit, 32, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_little_explode) {

    std::array<uint32_t, 2> in = {{0x56ef89ad, 0x1743cb02}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x89ad, 0x56ef, 0xcb02, 0x1743}};

    new_packer<little_octet_big_bit, little_octet_big_bit, 32, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(big_to_little_explode) {

    std::array<uint64_t, 1> in = {{0xef56127834cd90ab}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x781256ef, 0xab90cd34}};

    new_packer<big_octet_big_bit, little_octet_big_bit, 64, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(little_to_big_explode) {

    std::array<uint64_t, 1> in = {{0x90ab34cd1278ef56}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x56ef, 0x7812, 0xcd34, 0xab90}};

    new_packer<little_octet_big_bit, big_octet_big_bit, 64, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_SUITE_END()
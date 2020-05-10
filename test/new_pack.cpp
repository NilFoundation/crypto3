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

struct endians {
    typedef big_unit_big_bit<8> bb_8;
    typedef big_unit_big_bit<16> bb_16;
    typedef big_unit_big_bit<32> bb_32;
    typedef big_unit_big_bit<64> bb_64;

    typedef little_unit_big_bit<8> lb_8;
    typedef little_unit_big_bit<16> lb_16;
    typedef little_unit_big_bit<32> lb_32;
    typedef little_unit_big_bit<64> lb_64;

    typedef big_unit_little_bit<8> bl_8;
    typedef big_unit_little_bit<16> bl_16;
    typedef big_unit_little_bit<32> bl_32;
    typedef big_unit_little_bit<64> bl_64;

    typedef little_unit_little_bit<8> ll_8;
    typedef little_unit_little_bit<16> ll_16;
    typedef little_unit_little_bit<32> ll_32;
    typedef little_unit_little_bit<64> ll_64;

    virtual ~endians() {
    }
};

BOOST_AUTO_TEST_SUITE(pack_test_suite)

BOOST_FIXTURE_TEST_CASE(bb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0x4567, 0x89ab, 0xcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x01234567, 0x89abcdef}};

    new_packer<bb_16, bb_32, 16, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_explode, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x0123, 0x4567, 0x89ab, 0xcdef}};

    new_packer<bb_32, bb_16, 32, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_equal, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint32_t, 2> out {};

    new_packer<bb_32, bb_32, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(in == out);
}

BOOST_FIXTURE_TEST_CASE(lb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0x4567, 0x89ab, 0xcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x01234567, 0x89abcdef}};

    new_packer<lb_16, lb_32, 16, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_explode, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x0123, 0x4567, 0x89ab, 0xcdef}};

    new_packer<lb_32, lb_16, 32, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_equal, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint32_t, 2> out {};

    new_packer<lb_32, lb_32, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(in == out);
}

BOOST_FIXTURE_TEST_CASE(bb_to_lb_equal, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x67452301, 0xefcdab89}};

    new_packer<bb_32, lb_32, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_to_bb_equal, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x67452301, 0xefcdab89}};

    new_packer<lb_32, bb_32, 32, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_to_lb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0x4567, 0x89ab, 0xcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x67452301, 0xefcdab89}};

    new_packer<bb_16, lb_32, 16, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_to_bb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0x4567, 0x89ab, 0xcdef}};
    std::array<uint32_t, 2> out {};
    std::array<uint32_t, 2> res = {{0x67452301, 0xefcdab89}};

    new_packer<lb_16, bb_32, 16, 32>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_to_lb_explode, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x6745, 0x2301, 0xefcd, 0xab89}};

    new_packer<bb_32, lb_16, 32, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_to_bb_explode, endians) {

    std::array<uint32_t, 2> in = {{0x01234567, 0x89abcdef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x6745, 0x2301, 0xefcd, 0xab89}};

    new_packer<lb_32, bb_16, 32, 16>::pack(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(pack_n_test_suite)

BOOST_FIXTURE_TEST_CASE(bb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0x0123abcd456789ef}};

    new_packer<bb_16, bb_64, 16, 64>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_explode, endians) {

    std::array<uint64_t, 1> in = {{0x0123abcd456789ef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x0123, 0xabcd, 0x4567, 0x89ef}};

    new_packer<bb_64, bb_16, 64, 16>::pack_n(in.begin(), 1, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_equal, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint16_t, 4> out {};

    new_packer<bb_16, bb_16, 16, 16>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(in == out);
}

BOOST_FIXTURE_TEST_CASE(lb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0x0123abcd456789ef}};

    new_packer<lb_16, lb_64, 16, 64>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_explode, endians) {

    std::array<uint64_t, 1> in = {{0x0123abcd456789ef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x0123, 0xabcd, 0x4567, 0x89ef}};

    new_packer<lb_64, lb_16, 64, 16>::pack_n(in.begin(), 1, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_equal, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint16_t, 4> out {};

    new_packer<lb_16, lb_16, 16, 16>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(in == out);
}

BOOST_FIXTURE_TEST_CASE(bb_to_lb_equal, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x2301, 0xcdab, 0x6745, 0xef89}};

    new_packer<bb_16, lb_16, 16, 16>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_to_bb_equal, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0x2301, 0xcdab, 0x6745, 0xef89}};

    new_packer<lb_16, bb_16, 16, 16>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_to_lb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0xef896745cdab2301}};

    new_packer<bb_16, lb_64, 16, 64>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_to_bb_implode, endians) {

    std::array<uint16_t, 4> in = {{0x0123, 0xabcd, 0x4567, 0x89ef}};
    std::array<uint64_t, 1> out {};
    std::array<uint64_t, 1> res = {{0xef896745cdab2301}};

    new_packer<lb_16, bb_64, 16, 64>::pack_n(in.begin(), 4, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(bb_to_lb_explode, endians) {

    std::array<uint64_t, 1> in = {{0x0123abcd456789ef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0xef89, 0x6745, 0xcdab, 0x2301}};

    new_packer<bb_64, lb_16, 64, 16>::pack_n(in.begin(), 1, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_FIXTURE_TEST_CASE(lb_to_bb_explode, endians) {

    std::array<uint64_t, 1> in = {{0x0123abcd456789ef}};
    std::array<uint16_t, 4> out {};
    std::array<uint16_t, 4> res = {{0xef89, 0x6745, 0xcdab, 0x2301}};

    new_packer<lb_64, bb_16, 64, 16>::pack_n(in.begin(), 1, out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_SUITE_END()
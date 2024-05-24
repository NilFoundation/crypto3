//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE injector_test

#include <array>
#include <cstdint>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/detail/inject.hpp>

using namespace nil::crypto3;

template<std::size_t WordBits>
using fixed_uint = typename boost::uint_t<WordBits>::exact;

template<typename InputEndian, typename OutputEndian, std::size_t WordBits, std::size_t BlockWords, typename Block, typename Src>
void verify_injection(
    Src& src,
    size_t n_bits,
    size_t src_block_offset,
    size_t dst_coursor,
    Block& initial_dst,
    const Block& expected_dst
) {
    Block b_dst = initial_dst;
    size_t b_dst_coursor = dst_coursor;

    detail::injector<InputEndian, OutputEndian, WordBits, BlockWords>::inject(src, n_bits, b_dst, b_dst_coursor, src_block_offset);

    BOOST_CHECK_EQUAL_COLLECTIONS(b_dst.begin(), b_dst.end(), expected_dst.begin(), expected_dst.end());
    BOOST_CHECK_EQUAL(b_dst_coursor, dst_coursor + n_bits);
}

BOOST_AUTO_TEST_SUITE(InjectorTestSuit)

BOOST_AUTO_TEST_CASE(FirstBitInjectionBOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b10001111, 0b11111111};
    word_type w_src = 0b11111111;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 1, 0, 0, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(SecondBitInjectionBOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b01001111, 0b11111111};
    word_type w_src = 0b11111111;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 1, 0, 1, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToStartBOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b10101111, 0b11111111};
    word_type w_src = 0b10101010;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 3, 0, 0, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidBOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b01011111, 0b11111111};
    word_type w_src = 0b10101010;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 3, 0, 1, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidCrossWordBOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b00001110, 0b10111111};
    word_type w_src = 0b10101010;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 5, 0, 6, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidCrossLongWordBOBB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_big_bit;

    block_type initial_dst = {0b00000000'00000000, 0b00000000'00000000};
    block_type expected_dst = {0b00000000'00000101, 0b10111011'10000000};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 0, 13, initial_dst, expected_dst);
}

// Since there is not difference between big and little octet for 8-bit values, tests are the same
BOOST_AUTO_TEST_CASE(FirstBitInjectionLOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b10001111, 0b11111111};
    word_type w_src = 0b11111111;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 1, 0, 0, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(SecondBitInjectionLOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b01001111, 0b11111111};
    word_type w_src = 0b11111111;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 1, 0, 1, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToStartLOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b10101111, 0b11111111};
    word_type w_src = 0b10101010;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 3, 0, 0, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidLOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b01011111, 0b11111111};
    word_type w_src = 0b10101010;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 3, 0, 1, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidCrossWordLOBB) {
    using word_type = fixed_uint<8>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_big_bit;

    block_type initial_dst = {0b00001111, 0b11111111};
    block_type expected_dst = {0b00001110, 0b10111111};
    word_type w_src = 0b10101010;

    verify_injection<input_endian_type, output_endian_type, 8, 2>(w_src, 5, 0, 6, initial_dst, expected_dst);
}

// From here LOBB tests differs from BOBB as words are long
BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidCrossLongWordLOBB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_big_bit;

    block_type initial_dst = {0b00000000'00000000, 0b00000000'00000000};
    block_type expected_dst = {0b00000101'00000000, 0b10000000'10111011};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 0, 13, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidCrossLongWordBOLB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_little_bit;

    block_type initial_dst = {0b00000000'00000000, 0b00000000'00000000};
    block_type expected_dst = {0b00000000'10100000, 0b11011101'00000001};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 0, 13, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(BOBBMultipleBitToMidCrossLongWordLOLB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::big_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_little_bit;

    block_type initial_dst = {0b00000000'00000000, 0b00000000'00000000};
    block_type expected_dst = {0b10100000'00000000, 0b00000001'11011101};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 0, 13, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(LOBBMultipleBitToMidCrossLongWordLOLB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::little_octet_big_bit;
    using output_endian_type = stream_endian::little_octet_little_bit;

    block_type initial_dst = {0b00001001'10011001, 0b10010000'11111111};
    block_type expected_dst = {0b11001001'10011001, 0b10010001'10111011};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 0, 13, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(LOBBMultipleBitToMidCrossLongWordBOLB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::little_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_little_bit;

    block_type initial_dst = {0b10011001'00001001, 0b00000000'10010000};
    block_type expected_dst = {0b10011001'11001001, 0b10111011'10010001};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 0, 13, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(LOBBOffsetMultipleBitToMidCrossLongWordBOLB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::little_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_little_bit;

    block_type initial_dst = {0b10011001'00001001, 0b00000000'10010000};
    block_type expected_dst = {0b10011001'01101001, 0b10110111'10010001};
    word_type w_src = 0b10110111'01111011;

    verify_injection<input_endian_type, output_endian_type, 16, 2>(w_src, 12, 3, 13, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(LOBBOffsetMultipleBlockBitToMidCrossLongWordBOLB) {
    using word_type = fixed_uint<16>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::little_octet_big_bit;
    using output_endian_type = stream_endian::big_octet_little_bit;

    block_type initial_dst = {0b00000000'00000000, 0b00000000'10011001};
    block_type expected_dst = {0b11101100'11110110, 0b00011011'10011001};
    block_type b_src = {0b10110111'01111011, 0b11011110'11101101};

    verify_injection<input_endian_type, output_endian_type, 16, 2>(b_src, 20, 3, 2, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_CASE(LOBBOffsetMultipleBlockBitToMidCrossLongWordBOLB16Unit) {
    using word_type = fixed_uint<32>;
    using block_type = std::array<word_type, 2>;
    using input_endian_type = stream_endian::little_unit_big_bit<16>;
    using output_endian_type = stream_endian::big_unit_little_bit<16>;

    block_type initial_dst = {0b0000000000000000'0000000000000000, 0b0000000000000000'0000000000000000};
    block_type expected_dst = {0b0000000000000000'1110111100000000, 0b1110111011010110'0111011110111101};
    block_type b_src = {0b1011011101111011'1110111101110110, 0b0110111011110111'1101111011101101};

    verify_injection<input_endian_type, output_endian_type, 32, 2>(b_src, 40, 3, 23, initial_dst, expected_dst);
}

BOOST_AUTO_TEST_SUITE_END()

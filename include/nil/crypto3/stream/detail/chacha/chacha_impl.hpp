//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STREAM_CHACHA_IMPL_HPP
#define CRYPTO3_STREAM_CHACHA_IMPL_HPP

#include <nil/crypto3/stream/detail/chacha/chacha_policy.hpp>

#define CHACHA_QUARTER_ROUND(a, b, c, d) \
    do {                                 \
        a += b;                          \
        d ^= a;                          \
        d = policy_type::rotl<16>(d);    \
        c += d;                          \
        b ^= c;                          \
        b = policy_type::rotl<12>(b);    \
        a += b;                          \
        d ^= a;                          \
        d = policy_type::rotl<8>(d);     \
        c += d;                          \
        b ^= c;                          \
        b = policy_type::rotl<7>(b);     \
    } while (0)

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t Round, std::size_t IVSize, std::size_t KeyBits>
                struct chacha_impl {
                    typedef chacha_policy<Round, IVSize, KeyBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::min_key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::min_key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    inline static void chacha_x8(const std::array<std::uint8_t, block_size * 8> &block,
                                                 key_schedule_type &schedule) {
                        chacha_x4(block, schedule);
                        chacha_x4(std::array<std::uint8_t, block_size * 4>(block.begin() + block_size * 4, block.end()),
                                  schedule);
                    }

                    static void chacha_x4(const std::array<std::uint8_t, block_size * 4> &block,
                                          key_schedule_type &input) {
                        // TODO interleave rounds
                        for (size_t i = 0; i != 4; ++i) {
                            word_type x00 = input[0], x01 = input[1], x02 = input[2], x03 = input[3], x04 = input[4],
                                      x05 = input[5], x06 = input[6], x07 = input[7], x08 = input[8], x09 = input[9],
                                      x10 = input[10], x11 = input[11], x12 = input[12], x13 = input[13],
                                      x14 = input[14], x15 = input[15];

                            for (size_t r = 0; r != rounds / 2; ++r) {
                                CHACHA_QUARTER_ROUND(x00, x04, x08, x12);
                                CHACHA_QUARTER_ROUND(x01, x05, x09, x13);
                                CHACHA_QUARTER_ROUND(x02, x06, x10, x14);
                                CHACHA_QUARTER_ROUND(x03, x07, x11, x15);

                                CHACHA_QUARTER_ROUND(x00, x05, x10, x15);
                                CHACHA_QUARTER_ROUND(x01, x06, x11, x12);
                                CHACHA_QUARTER_ROUND(x02, x07, x08, x13);
                                CHACHA_QUARTER_ROUND(x03, x04, x09, x14);
                            }

                            x00 += input[0];
                            x01 += input[1];
                            x02 += input[2];
                            x03 += input[3];
                            x04 += input[4];
                            x05 += input[5];
                            x06 += input[6];
                            x07 += input[7];
                            x08 += input[8];
                            x09 += input[9];
                            x10 += input[10];
                            x11 += input[11];
                            x12 += input[12];
                            x13 += input[13];
                            x14 += input[14];
                            x15 += input[15];

                            boost::endian::store_little_u32(x00, block + 64 * i + 4 * 0);
                            boost::endian::store_little_u32(x01, block + 64 * i + 4 * 1);
                            boost::endian::store_little_u32(x02, block + 64 * i + 4 * 2);
                            boost::endian::store_little_u32(x03, block + 64 * i + 4 * 3);
                            boost::endian::store_little_u32(x04, block + 64 * i + 4 * 4);
                            boost::endian::store_little_u32(x05, block + 64 * i + 4 * 5);
                            boost::endian::store_little_u32(x06, block + 64 * i + 4 * 6);
                            boost::endian::store_little_u32(x07, block + 64 * i + 4 * 7);
                            boost::endian::store_little_u32(x08, block + 64 * i + 4 * 8);
                            boost::endian::store_little_u32(x09, block + 64 * i + 4 * 9);
                            boost::endian::store_little_u32(x10, block + 64 * i + 4 * 10);
                            boost::endian::store_little_u32(x11, block + 64 * i + 4 * 11);
                            boost::endian::store_little_u32(x12, block + 64 * i + 4 * 12);
                            boost::endian::store_little_u32(x13, block + 64 * i + 4 * 13);
                            boost::endian::store_little_u32(x14, block + 64 * i + 4 * 14);
                            boost::endian::store_little_u32(x15, block + 64 * i + 4 * 15);

                            input[12]++;
                            input[13] += input[12] < i;    // carry?
                        }
                    };
                }
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#undef CHACHA_QUARTER_ROUND
#endif    // CRYPTO3_CHACHA_IMPL_HPP
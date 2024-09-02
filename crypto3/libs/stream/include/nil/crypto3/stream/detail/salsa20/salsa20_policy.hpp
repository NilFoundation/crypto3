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

#ifndef CRYPTO3_STREAM_SALSA20_POLICY_HPP
#define CRYPTO3_STREAM_SALSA20_POLICY_HPP

#include <boost/endian/conversion.hpp>

#include <nil/crypto3/detail/inline_variable.hpp>

#include <nil/crypto3/stream/detail/basic_functions.hpp>

#define SALSA20_QUARTER_ROUND(x1, x2, x3, x4) \
    do {                                      \
        x2 ^= policy_type::rotl<7>(x1 + x4);  \
        x3 ^= policy_type::rotl<9>(x2 + x1);  \
        x4 ^= policy_type::rotl<13>(x3 + x2); \
        x1 ^= policy_type::rotl<18>(x4 + x3); \
    } while (0)

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t IVBits, std::size_t KeyBits, std::size_t Rounds>
                struct salsa20_policy : public basic_functions<32> {
                    typedef basic_functions<32> policy_type;

                    typedef typename policy_type::byte_type byte_type;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t rounds = Rounds;
                    BOOST_STATIC_ASSERT(Rounds % 2 == 0);

                    constexpr static const std::size_t value_bits = CHAR_BIT;
                    typedef byte_type value_type;

                    constexpr static const std::size_t block_size = 64;
                    constexpr static const std::size_t block_bits = block_size * value_bits;
                    typedef std::array<byte_type, block_size> block_type;

                    constexpr static const std::size_t min_key_bits = 16 * CHAR_BIT;
                    constexpr static const std::size_t max_key_bits = 32 * CHAR_BIT;
                    constexpr static const std::size_t key_bits = KeyBits;
                    constexpr static const std::size_t key_size = key_bits / CHAR_BIT;
                    BOOST_STATIC_ASSERT(min_key_bits <= KeyBits <= max_key_bits);
                    BOOST_STATIC_ASSERT(key_size % 16 == 0);
                    typedef std::array<byte_type, key_size> key_type;

                    constexpr static const std::size_t key_schedule_size = 16;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_size * word_bits;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;

                    constexpr static const std::size_t round_constants_size = 4;
                    typedef std::array<word_type, round_constants_size> round_constants_type;

                    CRYPTO3_INLINE_VARIABLE(round_constants_type, tau,
                                            ({0x61707865, 0x3120646e, 0x79622d36, 0x6b206574}));
                    CRYPTO3_INLINE_VARIABLE(round_constants_type, sigma,
                                            ({0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}));

                    constexpr static const std::size_t iv_bits = IVBits;
                    constexpr static const std::size_t iv_size = IVBits / CHAR_BIT;
                    typedef std::array<byte_type, iv_size> iv_type;

                    static void hsalsa20(word_type output[8], const key_schedule_type input) {
                        word_type x00 = input[0], x01 = input[1], x02 = input[2], x03 = input[3], x04 = input[4],
                                  x05 = input[5], x06 = input[6], x07 = input[7], x08 = input[8], x09 = input[9],
                                  x10 = input[10], x11 = input[11], x12 = input[12], x13 = input[13], x14 = input[14],
                                  x15 = input[15];

                        for (size_t i = 0; i != rounds / 2; ++i) {
                            SALSA20_QUARTER_ROUND(x00, x04, x08, x12);
                            SALSA20_QUARTER_ROUND(x05, x09, x13, x01);
                            SALSA20_QUARTER_ROUND(x10, x14, x02, x06);
                            SALSA20_QUARTER_ROUND(x15, x03, x07, x11);

                            SALSA20_QUARTER_ROUND(x00, x01, x02, x03);
                            SALSA20_QUARTER_ROUND(x05, x06, x07, x04);
                            SALSA20_QUARTER_ROUND(x10, x11, x08, x09);
                            SALSA20_QUARTER_ROUND(x15, x12, x13, x14);
                        }

                        output[0] = x00;
                        output[1] = x05;
                        output[2] = x10;
                        output[3] = x15;
                        output[4] = x06;
                        output[5] = x07;
                        output[6] = x08;
                        output[7] = x09;
                    }

                    static void salsa_core(block_type &block, const key_schedule_type &input) {
                        word_type x00 = input[0], x01 = input[1], x02 = input[2], x03 = input[3], x04 = input[4],
                                  x05 = input[5], x06 = input[6], x07 = input[7], x08 = input[8], x09 = input[9],
                                  x10 = input[10], x11 = input[11], x12 = input[12], x13 = input[13], x14 = input[14],
                                  x15 = input[15];

                        for (size_t i = 0; i != rounds / 2; ++i) {
                            SALSA20_QUARTER_ROUND(x00, x04, x08, x12);
                            SALSA20_QUARTER_ROUND(x05, x09, x13, x01);
                            SALSA20_QUARTER_ROUND(x10, x14, x02, x06);
                            SALSA20_QUARTER_ROUND(x15, x03, x07, x11);

                            SALSA20_QUARTER_ROUND(x00, x01, x02, x03);
                            SALSA20_QUARTER_ROUND(x05, x06, x07, x04);
                            SALSA20_QUARTER_ROUND(x10, x11, x08, x09);
                            SALSA20_QUARTER_ROUND(x15, x12, x13, x14);
                        }

                        boost::endian::store_little_u32(x00 + input[0], block[4 * 0]);
                        boost::endian::store_little_u32(x01 + input[1], block[4 * 1]);
                        boost::endian::store_little_u32(x02 + input[2], block[4 * 2]);
                        boost::endian::store_little_u32(x03 + input[3], block[4 * 3]);
                        boost::endian::store_little_u32(x04 + input[4], block[4 * 4]);
                        boost::endian::store_little_u32(x05 + input[5], block[4 * 5]);
                        boost::endian::store_little_u32(x06 + input[6], block[4 * 6]);
                        boost::endian::store_little_u32(x07 + input[7], block[4 * 7]);
                        boost::endian::store_little_u32(x08 + input[8], block[4 * 8]);
                        boost::endian::store_little_u32(x09 + input[9], block[4 * 9]);
                        boost::endian::store_little_u32(x10 + input[10], block[4 * 10]);
                        boost::endian::store_little_u32(x11 + input[11], block[4 * 11]);
                        boost::endian::store_little_u32(x12 + input[12], block[4 * 12]);
                        boost::endian::store_little_u32(x13 + input[13], block[4 * 13]);
                        boost::endian::store_little_u32(x14 + input[14], block[4 * 14]);
                        boost::endian::store_little_u32(x15 + input[15], block[4 * 15]);
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SALSA20_POLICY_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

                    static void chacha_x4(uint8_t output[64 * 4], key_schedule_type &input) {
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

                            store_le(x00, output + 64 * i + 4 * 0);
                            store_le(x01, output + 64 * i + 4 * 1);
                            store_le(x02, output + 64 * i + 4 * 2);
                            store_le(x03, output + 64 * i + 4 * 3);
                            store_le(x04, output + 64 * i + 4 * 4);
                            store_le(x05, output + 64 * i + 4 * 5);
                            store_le(x06, output + 64 * i + 4 * 6);
                            store_le(x07, output + 64 * i + 4 * 7);
                            store_le(x08, output + 64 * i + 4 * 8);
                            store_le(x09, output + 64 * i + 4 * 9);
                            store_le(x10, output + 64 * i + 4 * 10);
                            store_le(x11, output + 64 * i + 4 * 11);
                            store_le(x12, output + 64 * i + 4 * 12);
                            store_le(x13, output + 64 * i + 4 * 13);
                            store_le(x14, output + 64 * i + 4 * 14);
                            store_le(x15, output + 64 * i + 4 * 15);

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
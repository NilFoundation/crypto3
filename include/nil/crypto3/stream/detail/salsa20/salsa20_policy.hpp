//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_SALSA20_POLICY_HPP
#define CRYPTO3_STREAM_SALSA20_POLICY_HPP

#include <boost/container/small_vector.hpp>

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
                template<std::size_t IVBits, std::size_t KeyBits, std::size_t Rounds,
                         template<typename> class Allocator = std::allocator>
                struct salsa20_policy : public basic_functions<32> {
                    typedef basic_functions<32> policy_type;

                    typedef typename policy_type::byte_type byte_type;
                    typedef typename policy_type::word_type word_type;

                    template<typename T>
                    using allocator_type = Allocator<T>;

                    constexpr static const std::size_t rounds = Rounds;
                    BOOST_STATIC_ASSERT(Rounds % 2 == 0);

                    constexpr static const std::size_t value_bits = CHAR_BIT;
                    typedef byte_type value_type;

                    constexpr static const std::size_t block_values = 1;
                    constexpr static const std::size_t block_bits = block_values * value_bits;
                    typedef boost::container::small_vector<byte_type, block_values, Allocator<byte_type>> block_type;

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

                    static void salsa_core(uint8_t output[64], const key_schedule_type &input) {
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

                        store_le(x00 + input[0], output + 4 * 0);
                        store_le(x01 + input[1], output + 4 * 1);
                        store_le(x02 + input[2], output + 4 * 2);
                        store_le(x03 + input[3], output + 4 * 3);
                        store_le(x04 + input[4], output + 4 * 4);
                        store_le(x05 + input[5], output + 4 * 5);
                        store_le(x06 + input[6], output + 4 * 6);
                        store_le(x07 + input[7], output + 4 * 7);
                        store_le(x08 + input[8], output + 4 * 8);
                        store_le(x09 + input[9], output + 4 * 9);
                        store_le(x10 + input[10], output + 4 * 10);
                        store_le(x11 + input[11], output + 4 * 11);
                        store_le(x12 + input[12], output + 4 * 12);
                        store_le(x13 + input[13], output + 4 * 13);
                        store_le(x14 + input[14], output + 4 * 14);
                        store_le(x15 + input[15], output + 4 * 15);
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SALSA20_POLICY_HPP

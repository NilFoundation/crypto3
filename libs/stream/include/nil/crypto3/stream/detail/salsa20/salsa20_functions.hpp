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

#ifndef CRYPTO3_STREAM_SALSA20_FUNCTIONS_HPP
#define CRYPTO3_STREAM_SALSA20_FUNCTIONS_HPP

#include <nil/crypto3/stream/detail/salsa20/salsa20_policy.hpp>

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
                template<std::size_t IVSize, std::size_t KeyBits, std::size_t Rounds>
                struct salsa20_functions : public salsa20_policy<IVSize, KeyBits, Rounds> {
                    typedef salsa20_policy<IVSize, KeyBits, Rounds> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t word_bytes = word_bits / CHAR_BIT;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        // XSalsa20

                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 6] = boost::endian::native_to_little(
                                make_uint_t(iv[word_bytes * itr], iv[word_bytes * itr + 1], iv[word_bytes * itr + 2],
                                            iv[word_bytes * itr + 3]));
                        }

                        std::array<word_type, 8> hsalsa;
                        policy_type::hsalsa20(hsalsa.data(), schedule);

                        schedule[1] = hsalsa[0];
                        schedule[2] = hsalsa[1];
                        schedule[3] = hsalsa[2];
                        schedule[4] = hsalsa[3];
                        schedule[6] = boost::endian::native_to_little(
                            make_uint_t(iv[word_bytes * 4], iv[word_bytes * 4 + 1], iv[word_bytes * 4 + 2],
                                        iv[word_bytes * 4 + 3]));
                        schedule[7] = boost::endian::native_to_little(
                            make_uint_t(iv[word_bytes * 5], iv[word_bytes * 5 + 1], iv[word_bytes * 5 + 2],
                                        iv[word_bytes * 5 + 3]));
                        schedule[11] = hsalsa[4];
                        schedule[12] = hsalsa[5];
                        schedule[13] = hsalsa[6];
                        schedule[14] = hsalsa[7];

                        schedule[8] = 0;
                        schedule[9] = 0;

                        policy_type::salsa_core(block, schedule);
                        ++schedule[8];
                        schedule[9] += (schedule[8] == 0);
                    }
                };

                template<std::size_t Rounds>
                struct salsa20_functions<64, 128, Rounds> : public salsa20_policy<64, 128, Rounds> {
                    typedef salsa20_policy<64, 128, Rounds> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t word_bytes = word_bits / CHAR_BIT;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::tau()[0];
                        schedule[5] = policy_type::tau()[1];
                        schedule[10] = policy_type::tau()[2];
                        schedule[15] = policy_type::tau()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 1] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            schedule[itr + 11] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }

                    void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        // Salsa20
                        schedule[6] = boost::endian::native_to_little(make_uint_t(iv[0], iv[1], iv[2], iv[3]));
                        schedule[7] = boost::endian::native_to_little(make_uint_t(iv[4], iv[5], iv[6], iv[7]));
                        schedule[8] = 0;
                        schedule[9] = 0;

                        policy_type::salsa_core(block, schedule);
                        ++schedule[8];
                        schedule[9] += (schedule[8] == 0);
                    }
                };

                template<std::size_t Rounds>
                struct salsa20_functions<96, 128, Rounds> : public salsa20_policy<96, 128, Rounds> {
                    typedef salsa20_policy<96, 128, Rounds> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t word_bytes = word_bits / CHAR_BIT;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    void schedule_key(key_schedule_type &schedule, const key_type &key) {
                        schedule[0] = policy_type::tau()[0];
                        schedule[5] = policy_type::tau()[1];
                        schedule[10] = policy_type::tau()[2];
                        schedule[15] = policy_type::tau()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            schedule[itr + 1] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            schedule[itr + 11] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                        }
                    }

                    void schedule_iv(block_type &block, key_schedule_type &state, const iv_type &iv) {
                        // XSalsa20

                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            state[itr + 6] = boost::endian::native_to_little(
                                make_uint_t(iv[4 * itr], iv[4 * itr + 1], iv[4 * itr + 2], iv[4 * itr + 3]));
                        }

                        std::array<word_type, 8> hsalsa;
                        policy_type::hsalsa20(hsalsa.data(), state);

                        state[1] = hsalsa[0];
                        state[2] = hsalsa[1];
                        state[3] = hsalsa[2];
                        state[4] = hsalsa[3];
                        state[6] = boost::endian::native_to_little(
                            make_uint_t(iv[word_bytes * 4], iv[word_bytes * 4 + 1], iv[word_bytes * 4 + 2],
                                        iv[word_bytes * 4 + 3]));
                        state[7] = boost::endian::native_to_little(
                            make_uint_t(iv[word_bytes * 5], iv[word_bytes * 5 + 1], iv[word_bytes * 5 + 2],
                                        iv[word_bytes * 5 + 3]));
                        state[11] = hsalsa[4];
                        state[12] = hsalsa[5];
                        state[13] = hsalsa[6];
                        state[14] = hsalsa[7];

                        hsalsa.fill(0);

                        state[8] = 0;
                        state[9] = 0;

                        policy_type::salsa_core(block, state);
                        ++state[8];
                        state[9] += (state[8] == 0);
                    }
                };

                template<std::size_t Rounds>
                struct salsa20_functions<64, 256, Rounds> : public salsa20_policy<64, 256, Rounds> {
                    typedef salsa20_policy<64, 256, Rounds> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t word_bytes = word_bits / CHAR_BIT;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    void schedule_key(key_schedule_type &state, const key_type &key) {
                        state[0] = policy_type::sigma()[0];
                        state[5] = policy_type::sigma()[1];
                        state[10] = policy_type::sigma()[2];
                        state[15] = policy_type::sigma()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            state[itr + 1] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            state[itr + 11] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 16], key[4 * itr + 1 + 16], key[4 * itr + 2 + 16],
                                            key[4 * itr + 3 + 16]));
                        }
                    }

                    void schedule_iv(block_type &block, key_schedule_type &schedule, const iv_type &iv) {
                        // Salsa20
                        schedule[6] = boost::endian::native_to_little(make_uint_t(iv[0], iv[1], iv[2], iv[3]));
                        schedule[7] = boost::endian::native_to_little(make_uint_t(iv[4], iv[5], iv[6], iv[7]));
                        schedule[8] = 0;
                        schedule[9] = 0;

                        policy_type::salsa_core(block, schedule);
                        ++schedule[8];
                        schedule[9] += (schedule[8] == 0);
                    }
                };

                template<std::size_t Rounds>
                struct salsa20_functions<96, 256, Rounds> : public salsa20_policy<96, 256, Rounds> {
                    typedef salsa20_policy<96, 256, Rounds> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t word_bytes = word_bits / CHAR_BIT;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    constexpr static const std::size_t key_bits = policy_type::key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                    typedef typename policy_type::iv_type iv_type;

                    void schedule_key(key_schedule_type &state, const key_type &key) {
                        state[0] = policy_type::sigma()[0];
                        state[5] = policy_type::sigma()[1];
                        state[10] = policy_type::sigma()[2];
                        state[15] = policy_type::sigma()[3];


                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            state[itr + 1] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr], key[4 * itr + 1], key[4 * itr + 2], key[4 * itr + 3]));
                            state[itr + 11] = boost::endian::native_to_little(
                                make_uint_t(key[4 * itr + 16], key[4 * itr + 1 + 16], key[4 * itr + 2 + 16],
                                            key[4 * itr + 3 + 16]));
                        }
                    }

                    void schedule_iv(block_type &block, key_schedule_type &state, const iv_type &iv) {
                        // XSalsa20

                        for (std::uint8_t itr = 0; itr < 4; itr++) {
                            state[itr + 6] = boost::endian::native_to_little(
                                make_uint_t(iv[4 * itr], iv[4 * itr + 1], iv[4 * itr + 2], iv[4 * itr + 3]));
                        }

                        std::array<word_type, 8> hsalsa;
                        policy_type::hsalsa20(hsalsa.data(), state);

                        state[1] = hsalsa[0];
                        state[2] = hsalsa[1];
                        state[3] = hsalsa[2];
                        state[4] = hsalsa[3];
                        state[6] = boost::endian::native_to_little(
                            make_uint_t(iv[word_bytes * 4], iv[word_bytes * 4 + 1], iv[word_bytes * 4 + 2],
                                        iv[word_bytes * 4 + 3]));
                        state[7] = boost::endian::native_to_little(
                            make_uint_t(iv[word_bytes * 5], iv[word_bytes * 5 + 1], iv[word_bytes * 5 + 2],
                                        iv[word_bytes * 5 + 3]));
                        state[11] = hsalsa[4];
                        state[12] = hsalsa[5];
                        state[13] = hsalsa[6];
                        state[14] = hsalsa[7];

                        state[8] = 0;
                        state[9] = 0;

                        policy_type::salsa_core(block, state);
                        ++state[8];
                        state[9] += (state[8] == 0);
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SALSA20_FUNCTIONS_HPP

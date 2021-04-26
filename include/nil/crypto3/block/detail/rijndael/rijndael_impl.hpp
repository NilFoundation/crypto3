//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_RIJNDAEL_IMPL_HPP
#define CRYPTO3_RIJNDAEL_IMPL_HPP

#include <nil/crypto3/block/algorithm/move.hpp>

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @cond DETAIL_IMPL
             */
            namespace detail {
                template<std::size_t KeyBitsImpl, std::size_t BlockBitsImpl, typename PolicyType>
                class rijndael_impl {
                    typedef PolicyType policy_type;

                    typedef typename policy_type::key_type key_type;
                    typedef typename policy_type::key_schedule_type key_schedule_type;
                    typedef typename policy_type::key_schedule_word_type key_schedule_word_type;

                    typedef typename policy_type::block_type block_type;

                    typedef typename policy_type::constants_type constants_type;
                    typedef typename policy_type::shift_offsets_type shift_offsets_type;
                    typedef typename policy_type::mm_type mm_type;

                    BOOST_STATIC_ASSERT(KeyBitsImpl == PolicyType::key_bits);
                    BOOST_STATIC_ASSERT(BlockBitsImpl == PolicyType::block_bits);

                    static inline key_schedule_word_type sub_word(const key_schedule_word_type &x,
                                                                  const constants_type &constants) {
                        key_schedule_word_type result = {0};

                        for (std::size_t i = 0; i < policy_type::word_bytes; ++i) {
                            result =
                                result << CHAR_BIT | constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(x, i)];
                        }

                        return result;
                    }

                    static inline void sub_bytes(block_type &state, const constants_type &sbox) {

                        for (std::size_t i = 0; i < policy_type::word_bytes * policy_type::block_words; ++i) {
                            state[i] = sbox[state[i]];
                        }
                    }

                    static inline void shift_rows(block_type &state, const shift_offsets_type &offset) {
                        std::array<typename policy_type::byte_type, policy_type::block_words> tmp = {0};

                        // row 0 never gets shifted

                        for (std::size_t row = 1; row < policy_type::word_bytes; ++row) {
                            const std::size_t off = offset[row - 1];

                            for (std::size_t i = 0; i < off; ++i) {
                                tmp[i] = state[i * policy_type::word_bytes + row];
                            }

                            for (std::size_t i = 0; i < policy_type::block_words - 1; ++i) {
                                state[i * policy_type::word_bytes + row] =
                                    state[(i + off) * policy_type::word_bytes + row];
                            }

                            for (std::size_t i = 0; i < off; ++i) {
                                state[(policy_type::block_words - 1 - i) * policy_type::word_bytes + row] =
                                    tmp[off - 1 - i];
                            }
                        }
                    }

                    template<typename StateType>
                    static inline block_type mix_columns(const StateType &state, const mm_type &mm) {
                        block_type tmp = {0};


                        for (std::size_t col = 0; col < policy_type::block_words; ++col) {

                            for (std::size_t row = 0; row < policy_type::word_bytes; ++row) {

                                for (std::size_t k = 0; k < policy_type::word_bytes; ++k) {
                                    tmp[col * policy_type::word_bytes + row] ^=
                                        policy_type::mul(mm[row * policy_type::word_bytes + k],
                                                         state[col * policy_type::word_bytes + k]);
                                }
                            }
                        }

                        return tmp;
                    }

                    template<typename InputIterator>
                    static inline void add_round_key(block_type &state, InputIterator first, InputIterator last) {
                        BOOST_ASSERT(std::distance(first, last) == policy_type::block_words &&
                                     state.size() == policy_type::block_bytes);


                        for (std::size_t i = 0; i < policy_type::block_words && first != last; ++i && ++first) {

                            for (std::size_t j = 0; j < policy_type::word_bytes; ++j) {
                                state[i * policy_type::word_bytes + j] ^=
                                    ::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(*first,
                                                                                     policy_type::word_bytes - (j + 1));
                            }
                        }
                    }

                    static inline void apply_round(std::uint8_t round, block_type &state, const key_schedule_type &w,
                                                   const constants_type &sbox, const shift_offsets_type &offsets,
                                                   const mm_type &mm) {
                        sub_bytes(state, sbox);
                        shift_rows(state, offsets);
                        state = mix_columns(state, mm);
                        add_round_key(state, w.begin() + round * policy_type::block_words,
                                      w.begin() + (round + 1) * policy_type::block_words);
                    }

                public:
                    static typename policy_type::block_type encrypt_block(const block_type &plaintext,
                                                                          const key_schedule_type &encryption_key) {
                        block_type state = plaintext;

                        add_round_key(state, encryption_key.begin(), encryption_key.begin() + policy_type::block_words);


                        for (std::size_t round = 1; round < policy_type::rounds; ++round) {
                            apply_round(round, state, encryption_key, policy_type::constants,
                                        policy_type::shift_offsets, policy_type::mm);
                        }

                        sub_bytes(state, policy_type::constants);
                        shift_rows(state, policy_type::shift_offsets);
                        add_round_key(state, encryption_key.begin() + policy_type::rounds * policy_type::block_words,
                                      encryption_key.begin() + (policy_type::rounds + 1) * policy_type::block_words);

                        return state;
                    }

                    static typename policy_type::block_type decrypt_block(const block_type &plaintext,
                                                                          const key_schedule_type &decryption_key) {
                        block_type state = plaintext;

                        add_round_key(state, decryption_key.begin() + policy_type::rounds * policy_type::block_words,
                                      decryption_key.begin() + (policy_type::rounds + 1) * policy_type::block_words);


                        for (std::size_t round = policy_type::rounds - 1; round > 0; --round) {
                            apply_round(round, state, decryption_key, policy_type::inverted_constants,
                                        policy_type::inverted_shift_offsets, policy_type::inverted_mm);
                        }

                        sub_bytes(state, policy_type::inverted_constants);
                        shift_rows(state, policy_type::inverted_shift_offsets);
                        add_round_key(state, decryption_key.begin(), decryption_key.begin() + policy_type::block_words);

                        return state;
                    }

                    static void schedule_key(const key_type &key, key_schedule_type &encryption_key,
                                             key_schedule_type &decryption_key) {
                        // the first key_words words are the original key
                        ::nil::crypto3::detail::pack<stream_endian::big_octet_big_bit,
                                                     stream_endian::little_octet_big_bit, CHAR_BIT,
                                                     policy_type::word_bits>(
                            key.begin(), key.begin() + policy_type::key_words * policy_type::word_bytes,
                            encryption_key.begin());


                        for (std::size_t i = policy_type::key_words; i < policy_type::key_schedule_words; ++i) {
                            typename policy_type::key_schedule_word_type tmp = encryption_key[i - 1];
                            if (i % policy_type::key_words == 0) {
                                tmp = sub_word(policy_type::rotate_left(tmp), policy_type::constants) ^
                                      policy_type::round_constants[i / policy_type::key_words - 1];
                            } else if (policy_type::key_words > 6 && i % policy_type::key_words == 4) {
                                tmp = sub_word(tmp, policy_type::constants);
                            }
                            encryption_key[i] = encryption_key[i - policy_type::key_words] ^ tmp;
                        }

                        std::array<typename policy_type::byte_type, policy_type::key_schedule_bytes> bekey = {0};
                        ::nil::crypto3::detail::pack<stream_endian::little_octet_big_bit,
                                                     stream_endian::big_octet_big_bit, policy_type::word_bits,
                                                     CHAR_BIT>(encryption_key.begin(), encryption_key.end(),
                                                               bekey.begin());


                        for (std::uint8_t round = 1; round < policy_type::rounds; ++round) {
                            move(mix_columns(boost::adaptors::slice(bekey, round * policy_type::block_bytes,
                                                                    (round + 1) * policy_type::block_bytes),
                                             policy_type::inverted_mm),
                                 bekey.begin() + round * policy_type::block_bytes);
                        }

                        ::nil::crypto3::detail::pack<stream_endian::big_octet_big_bit,
                                                     stream_endian::little_octet_big_bit, CHAR_BIT,
                                                     policy_type::word_bits>(bekey.begin(), bekey.end(),
                                                                             decryption_key.begin());
                    }
                };
            }    // namespace detail
            /*!
             * @endcond
             */
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RIJNDAEL_IMPL_HPP

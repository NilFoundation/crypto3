//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RIJNDAEL_IMPL_HPP
#define CRYPTO3_RIJNDAEL_IMPL_HPP

#include <nil/crypto3/block/algorithm/move.hpp>

#include <nil/crypto3/block/detail/stream_endian.hpp>
#include <nil/crypto3/block/detail/pack.hpp>

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

                    BOOST_STATIC_ASSERT(KeyBitsImpl == PolicyType::key_bits);
                    BOOST_STATIC_ASSERT(BlockBitsImpl == PolicyType::block_bits);

                    static inline typename policy_type::key_schedule_word_type sub_word(
                            const typename policy_type::key_schedule_word_type &x,
                            const typename policy_type::constants_type &constants) {
                        typename policy_type::key_schedule_word_type result = {0};
#pragma clang loop unroll(full)
                        for (uint8_t i = 0; i < policy_type::word_bytes; ++i) {
                            result = result << CHAR_BIT | constants[get_byte(i, x)];
                        }

                        return result;
                    }

                    static inline void sub_bytes(typename policy_type::block_type &state,
                                                 const typename policy_type::constants_type &sbox) {
#pragma clang loop unroll(full)
                        for (int i = 0; i < policy_type::word_bytes * policy_type::block_words; ++i) {
                            state[i] = sbox[state[i]];
                        }
                    }

                    static inline void shift_rows(typename policy_type::block_type &state,
                                                  const typename policy_type::shift_offsets_type &offset) {
                        std::array<typename policy_type::byte_type, policy_type::block_words> tmp = {0};

                        // row 0 never gets shifted
#pragma clang loop unroll(full)
                        for (int row = 1; row < policy_type::word_bytes; ++row) {
                            const int off = offset[row - 1];
#pragma clang loop unroll(full)
                            for (int i = 0; i < off; ++i) {
                                tmp[i] = state[i * policy_type::word_bytes + row];
                            }
#pragma clang loop unroll(full)
                            for (int i = 0; i < policy_type::block_words - 1; ++i) {
                                state[i * policy_type::word_bytes + row] = state[(i + off) * policy_type::word_bytes +
                                                                                 row];
                            }
#pragma clang loop unroll(full)
                            for (int i = 0; i < off; ++i) {
                                state[(policy_type::block_words - 1 - i) * policy_type::word_bytes + row] = tmp[off -
                                                                                                                1 - i];
                            }
                        }
                    }

                    template<typename StateType>
                    static inline typename policy_type::block_type mix_columns(const StateType &state,
                                                                               const typename policy_type::mm_type &mm) {
                        typename policy_type::block_type tmp = {0};

#pragma clang loop unroll(full)
                        for (int col = 0; col < policy_type::block_words; ++col) {
#pragma clang loop unroll(full)
                            for (int row = 0; row < policy_type::word_bytes; ++row) {
#pragma clang loop unroll(full)
                                for (int k = 0; k < policy_type::word_bytes; ++k) {
                                    tmp[col * policy_type::word_bytes + row] ^= policy_type::mul(
                                            mm[row * policy_type::word_bytes + k],
                                            state[col * policy_type::word_bytes + k]);
                                }
                            }
                        }

                        return tmp;
                    }

                    template<typename InputIterator>
                    static inline void add_round_key(typename policy_type::block_type &state, InputIterator first,
                                                     InputIterator last) {
                        BOOST_ASSERT(std::distance(first, last) == policy_type::block_words &&
                                     state.size() == policy_type::block_bytes);

#pragma clang loop unroll(full)
                        for (std::uint8_t i = 0; i < policy_type::block_words && first != last; ++i && ++first) {
#pragma clang loop unroll(full)
                            for (std::uint8_t j = 0; j < policy_type::word_bytes; ++j) {
                                state[i * policy_type::word_bytes + j] ^= get_byte(policy_type::word_bytes - (j + 1),
                                        *first);
                            }
                        }
                    }

                    static void apply_round(std::uint8_t round, typename policy_type::block_type &state,
                                            const typename policy_type::key_schedule_type &w,
                                            const typename policy_type::constants_type &sbox,
                                            const typename policy_type::shift_offsets_type &offsets,
                                            const typename policy_type::mm_type &mm) {
                        sub_bytes(state, sbox);
                        shift_rows(state, offsets);
                        state = mix_columns(state, mm);
                        add_round_key(state, w.begin() + round * policy_type::block_words,
                                w.begin() + (round + 1) * policy_type::block_words);
                    }

                public:

                    static typename policy_type::block_type encrypt_block(
                            const typename policy_type::block_type &plaintext,
                            const typename policy_type::key_schedule_type &encryption_key) {
                        typename policy_type::block_type state = plaintext;

                        add_round_key(state, encryption_key.begin(), encryption_key.begin() + policy_type::block_words);

#pragma clang loop unroll(full)
                        for (std::uint8_t round = 1; round < policy_type::rounds; ++round) {
                            apply_round(round, state, encryption_key, policy_type::constants,
                                    policy_type::shift_offsets, policy_type::mm);
                        }

                        sub_bytes(state, policy_type::constants);
                        shift_rows(state, policy_type::shift_offsets);
                        add_round_key(state, encryption_key.begin() + policy_type::rounds * policy_type::block_words,
                                encryption_key.begin() + (policy_type::rounds + 1) * policy_type::block_words);

                        return state;
                    }

                    static typename policy_type::block_type decrypt_block(
                            const typename policy_type::block_type &plaintext,
                            const typename policy_type::key_schedule_type &decryption_key) {
                        typename policy_type::block_type state = plaintext;

                        add_round_key(state, decryption_key.begin() + policy_type::rounds * policy_type::block_words,
                                decryption_key.begin() + (policy_type::rounds + 1) * policy_type::block_words);

#pragma clang loop unroll(full)
                        for (std::uint8_t round = policy_type::rounds - 1; round > 0; --round) {
                            apply_round(round, state, decryption_key, policy_type::inverted_constants,
                                    policy_type::inverted_shift_offsets, policy_type::inverted_mm);
                        }

                        sub_bytes(state, policy_type::inverted_constants);
                        shift_rows(state, policy_type::inverted_shift_offsets);
                        add_round_key(state, decryption_key.begin(), decryption_key.begin() + policy_type::block_words);

                        return state;
                    }

                    static void schedule_key(const typename policy_type::key_type &key,
                                             typename policy_type::key_schedule_type &encryption_key,
                                             typename policy_type::key_schedule_type &decryption_key) {
                        // the first key_words words are the original key
                        pack<stream_endian::little_octet_big_bit, CHAR_BIT, policy_type::word_bits>(key.begin(),
                                key.begin() + policy_type::key_words * policy_type::word_bytes, encryption_key.begin(),
                                encryption_key.begin() + policy_type::key_words);

#pragma clang loop unroll(full)
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
                        pack<stream_endian::little_octet_big_bit, policy_type::word_bits, CHAR_BIT>(encryption_key,
                                bekey);

#pragma clang loop unroll(full)
                        for (std::uint8_t round = 1; round < policy_type::rounds; ++round) {
                            move(mix_columns(boost::adaptors::slice(bekey, round * policy_type::block_bytes,
                                    (round + 1) * policy_type::block_bytes), policy_type::inverted_mm),
                                    bekey.begin() + round * policy_type::block_bytes);
                        }

                        pack<stream_endian::little_octet_big_bit, CHAR_BIT, policy_type::word_bits>(bekey,
                                decryption_key);
                    }
                };
            }
            /*!
             * @endcond
             */
        }
    }
}

#endif //CRYPTO3_RIJNDAEL_IMPL_HPP

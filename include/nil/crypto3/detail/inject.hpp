//---------------------------------------------------------------------------//
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_INJECT_HASH_HPP
#define CRYPTO3_INJECT_HASH_HPP

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/endian_shift.hpp>
#include <nil/crypto3/detail/reverser.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            // Word injectors inject first n_bits of w_src words into b_dst block.
            // Bits are inserted to block's [b_dst_cursor, b_dst_cursor + n_bits - 1] positions
            template<typename InputEndian, typename OutputEndian, std::size_t WordBits, std::size_t BlockWords>
            struct word_injector;

            template<int UnitBits, template<int> class InputEndian, template<int> class OutputEndian, std::size_t WordBits, std::size_t BlockWords>
            struct word_injector<InputEndian<UnitBits>, OutputEndian<UnitBits>, WordBits, BlockWords>
                : public basic_functions<WordBits> {

                constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                constexpr static const std::size_t block_bits = WordBits * BlockWords;
                typedef typename basic_functions<WordBits>::word_type word_type;

                typedef std::array<word_type, BlockWords> block_type;

                static void inject(word_type w_src, std::size_t n_bits, block_type &b_dst, std::size_t &b_dst_cursor) {
                    // Check whether we fall out of the block
                    if (b_dst_cursor + n_bits > block_bits) {
                        return;
                    }

                    // Calculate start and end words in destination block that will be affected
                    std::size_t start_word_index = b_dst_cursor / WordBits;
                    std::size_t end_word_index = (b_dst_cursor + n_bits - 1) / WordBits;

                    using operation_endian = stream_endian::big_unit_big_bit<UnitBits>;

                    using block_to_operation_unit_reverser = unit_reverser<OutputEndian<UnitBits>, operation_endian, UnitBits>;
                    using block_to_operation_bit_reverser = bit_reverser<OutputEndian<UnitBits>, operation_endian, UnitBits>;

                    // Convert affected destination words to big endian (no-op if already so)
                    for (std::size_t i = start_word_index; i <= end_word_index; ++i) {
                        block_to_operation_bit_reverser::reverse(b_dst[i]);
                        block_to_operation_unit_reverser::reverse(b_dst[i]);
                    }

                    using word_to_operation_unit_reverser = unit_reverser<InputEndian<UnitBits>, operation_endian, UnitBits>;
                    using word_to_operation_bit_reverser = bit_reverser<InputEndian<UnitBits>, operation_endian, UnitBits>;
                    word_to_operation_unit_reverser::reverse(w_src);
                    word_to_operation_bit_reverser::reverse(w_src);

                    while (n_bits > 0) {
                        // Calculate current word and bit offset in destination block
                        std::size_t cur_word_idx = b_dst_cursor / WordBits;
                        std::size_t cur_word_bits_offset = b_dst_cursor % WordBits;

                        // Determine how many bits can be injected to the current word
                        std::size_t bits_this_round = std::min(n_bits, WordBits - cur_word_bits_offset);

                        // Extract bits_this_round bits from w_src
                        // We have to pass `word_type` to bits funcs, so small types (e.g. uint8) are not promoted to int after ~()
                        word_type src_mask = high_bits<WordBits, word_type>(~word_type(), bits_this_round);
                        word_type bits_to_inject = w_src & src_mask;
                        // Shift bits_to_inject to align with the destination position
                        bits_to_inject = unbounded_shr(bits_to_inject, cur_word_bits_offset);

                        // Which bits in dst word we have to keep
                        word_type dst_mask = high_bits<WordBits, word_type>(~word_type(), cur_word_bits_offset) |
                                            low_bits<WordBits, word_type>(~word_type(), WordBits - cur_word_bits_offset - bits_this_round);

                        b_dst[cur_word_idx] &= dst_mask; // Clear the bits at the destination
                        b_dst[cur_word_idx] |= bits_to_inject; // Set the new bits

                        // Update cursor and remaining bits for next round, shift w_src
                        w_src = unbounded_shl(w_src, bits_this_round);
                        b_dst_cursor += bits_this_round;
                        n_bits -= bits_this_round;
                    }

                    // Convert affected destination words back to their original endian
                    for (std::size_t i = start_word_index; i <= end_word_index; ++i) {
                        block_to_operation_bit_reverser::reverse(b_dst[i]);
                        block_to_operation_unit_reverser::reverse(b_dst[i]);
                    }
                }
            };

            template<typename InputEndian, typename OutputEndian, std::size_t WordBits, std::size_t BlockWords>
            struct injector : word_injector<InputEndian, OutputEndian, WordBits, BlockWords> {

                constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                constexpr static const std::size_t block_bits = WordBits * BlockWords;
                typedef typename basic_functions<WordBits>::word_type word_type;

                typedef std::array<word_type, BlockWords> block_type;

                /**
                 * @brief Injects a portion of one block into another.
                 *
                 * Injects a specified number of bits from the source block into the destination block
                 * according to endianness. `b_dst_cursor` is updated to reflect the new position
                 * after injection.
                 *
                 * @param b_src Source block from which bits are to be injected.
                 * @param n_bits Number of bits in `b_src` that are to be injected.
                 * @param b_dst Destination block where bits from `b_src` will be injected.
                 * @param b_dst_cursor Reference to the running count of bits injected into `b_dst`.
                 * @param b_src_offset_bits The bit position within `b_src` from where to start reading bits (default is 0).
                 *
                 * @note Checks if the total bits (`n_bits` + `b_dst_cursor`) exceed the size of `b_dst`
                 *       and does nothing in this case.
                 */
                static void inject(const block_type &b_src, std::size_t n_bits, block_type &b_dst,
                                   std::size_t &b_dst_cursor, const std::size_t b_src_offset_bits = 0) {
                    if (n_bits + b_dst_cursor <= block_bits) {

                        std::size_t first_word_ind = b_src_offset_bits / word_bits;
                        std::size_t word_shift = b_src_offset_bits % word_bits;

                        std::size_t first_word_seen =
                            (word_bits - word_shift) > n_bits ? n_bits : (word_bits - word_shift);

                        inject(b_src[first_word_ind], first_word_seen, b_dst, b_dst_cursor, word_shift);

                        n_bits -= first_word_seen;

                        for (std::size_t i = 0; i < (n_bits / word_bits); i++) {
                            inject(b_src[first_word_ind + 1 + i], word_bits, b_dst, b_dst_cursor);
                        }

                        if (n_bits % word_bits) {
                            inject(b_src[first_word_ind + 1 + n_bits / word_bits], n_bits % word_bits, b_dst,
                                   b_dst_cursor);
                        }
                    }
                }

                /**
                 * @brief Injects a portion of a word into a block.
                 *
                 * Injects a specified number of bits from a source word into the destination block (b_dst)
                 * according to endianness. `b_dst_cursor` is updated to reflect the new position
                 * after injection.
                 *
                 * @param w_src The source word from which bits are to be injected.
                 * @param n_bits The number of bits in w_src to be injected into b_dst.
                 * @param b_dst The destination block where bits from w_src will be injected.
                 * @param b_dst_cursor A reference to the running position in b_dst where the next bit will be injected.
                 * @param src_word_offset The bit position within w_src from where to start reading bits (default is 0).
                 */
                static void inject(const word_type w_src, const std::size_t n_bits, block_type &b_dst, std::size_t &b_dst_cursor,
                                   std::size_t src_word_offset = 0) {

                    word_type shifted_word = w_src;

                    if (src_word_offset > 0) {
                        endian_shift<InputEndian, word_bits>::to_msb(shifted_word, src_word_offset);
                    }

                    word_injector<InputEndian, OutputEndian, WordBits, BlockWords>::inject(shifted_word, n_bits, b_dst,
                                                                                       b_dst_cursor);
                }
            };
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_INJECT_HASH_HPP

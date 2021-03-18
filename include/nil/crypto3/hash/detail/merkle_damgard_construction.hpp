//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP
#define CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            /*!
             * @brief
             * @tparam DigestEndian
             * @tparam DigestBits
             * @tparam IV
             * @tparam Compressor
             * @tparam Finalizer
             *
             * The Merkle-Damgård construction builds a block hashes from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             *
             * @note http://www.merkle.com/papers/Thesis1979.pdf
             */
            template<typename Params, typename IV, typename Compressor, typename Padding,
                     typename Finalizer = detail::nop_finalizer>
            class merkle_damgard_construction {
            public:
                typedef IV iv_generator;
                typedef Compressor compressor_functor;
                typedef Padding padding_functor;
                typedef Finalizer finalizer_functor;

                typedef typename Params::digest_endian endian_type;

                constexpr static const std::size_t word_bits = compressor_functor::word_bits;
                typedef typename compressor_functor::word_type word_type;

                constexpr static const std::size_t state_bits = compressor_functor::state_bits;
                constexpr static const std::size_t state_words = compressor_functor::state_words;
                typedef typename compressor_functor::state_type state_type;

                constexpr static const std::size_t block_bits = compressor_functor::block_bits;
                constexpr static const std::size_t block_words = compressor_functor::block_words;
                typedef typename compressor_functor::block_type block_type;

                constexpr static const std::size_t digest_bits = Params::digest_bits;
                constexpr static const std::size_t digest_bytes = digest_bits / octet_bits;
                constexpr static const std::size_t digest_words = digest_bits / word_bits;
                typedef static_digest<digest_bits> digest_type;

            protected:
                constexpr static const std::size_t length_bits = Params::length_bits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits = length_bits < word_bits ? word_bits :
                                                                      length_bits > 64        ? 64 :
                                                                                                length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;
                constexpr static const std::size_t length_words = length_bits / word_bits;
                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

            public:
                template<typename Integer = std::size_t>
                inline merkle_damgard_construction &process_block(const block_type &block, Integer seen = Integer()) {
                    compressor_functor::process_block(state_, block);
                    return *this;
                }

                inline digest_type digest(const block_type &block = block_type(),
                                          length_type total_seen = length_type()) {
                    using namespace nil::crypto3::detail;

                    block_type b = block;
                    std::size_t block_seen = total_seen % block_bits;
                    // Process block if block is full
                    if (total_seen && !block_seen)
                        process_block(b);

                    // Pad last message block
                    padding_functor padding;
                    padding(b, block_seen);

                    // Process block if total length cannot be appended
                    if (block_seen + length_bits > block_bits) {
                        process_block(b);
                        std::fill(b.begin(), b.end(), 0);
                    }

                    // Append total length to the last block
                    append_length<int>(b, total_seen);

                    // Process the last block
                    process_block(b);

                    // Apply finalizer
                    finalizer_functor()(state_);

                    // Convert digest to byte representation
                    digest_type d;
                    pack_from<endian_type, word_bits, octet_bits>(state_.begin(), state_.end(), d.begin());
                    return d;
                }

                merkle_damgard_construction() {
                    reset();
                }

                inline void reset(const state_type &s) {
                    state_ = s;
                }

                inline void reset() {
                    iv_generator iv;
                    reset(iv());
                }

                inline const state_type &state() const {
                    return state_;
                }

            protected:
                template<typename Dummy>
                typename std::enable_if<length_bits && sizeof(Dummy)>::type append_length(block_type &block,
                                                                                          length_type length) {
                    using namespace nil::crypto3::detail;

                    std::array<length_type, 1> length_array = {{length}};
                    std::array<word_type, length_words> length_words_array;
                    pack<endian_type, endian_type, length_bits, word_bits>(length_array.begin(), length_array.end(),
                                                                           length_words_array.begin());
                    // Append length
                    for (std::size_t i = length_words; i; --i)
                        block[block_words - i] = length_words_array[length_words - i];
                }

                template<typename Dummy>
                typename std::enable_if<!(length_bits && sizeof(Dummy))>::type append_length(block_type &block,
                                                                                             length_type length) {
                    // No appending requested, so nothing to do
                }
                state_type state_;
            };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MERKLE_DAMGARD_BLOCK_HASH_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP
#define CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/detail/endian_shift.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

#include <boost/utility/enable_if.hpp>

#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @brief
             * @tparam DigestEndian
             * @tparam DigestBits
             * @tparam IV
             * @tparam Compressor
             * @tparam Finalizer
             *
             * The Merkle-Damgård construction builds a block hash from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             *
             * @note http://www.merkle.com/papers/Thesis1979.pdf
             */
            template<typename Params, typename IV, typename Compressor, typename Finalizer = nop_finalizer>
            class merkle_damgard_construction {
            public:
                typedef IV iv_generator;
                typedef Compressor compressor_functor;
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
                constexpr static const std::size_t length_type_bits =
                    length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;
                constexpr static const std::size_t length_words = length_bits / word_bits;
                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

                typedef ::nil::crypto3::detail::injector<endian_type, word_bits, block_words, block_bits> injector;
            public:
                inline merkle_damgard_construction &process_block(const block_type &block) {
                    compressor_functor::process_block(state_, block);
                    return *this;
                }

                inline digest_type end_message(const block_type &block = block_type(),
                                               length_type seen = length_type()) {
                    digest_type d = digest(block, seen);
                    reset();
                    return d;
                }
                

                inline digest_type digest(const block_type &block = block_type(), length_type seen = length_type()) {
                    
                    using namespace nil::crypto3::detail;
                    block_type b;
                    length_type head_bits = seen % block_bits; // the number of significant bits in block
                    length_type head_words = (seen / word_bits) % block_words; // the number of significant block words

                    // Case of full block
                    if (!head_bits) {
                        std::fill(b.begin(), b.end(), 0);
                    }
                    // Case of incomplete block 
                    else {
                        
                        std::move(block.begin(), block.end(), b.begin());

                        // Remove possible garbage from the block
                        std::fill(b.begin() + head_words + 1, b.end(), 0);
                        
                    }
                    // Fill the block with bit 1 and length
                    std::array<bool, word_bits> bit_one = {{1}};
                    std::array<word_type, 1> bit_one_word = {0};
                    pack<endian_type, 1, word_bits>(bit_one, bit_one_word);
                    injector::inject(bit_one_word[0], 1, b, head_bits);
                    
                    // Create new block if there is no sufficient data to hold length in the current block
                    if (head_bits > block_bits - length_bits - 1) {
                        process_block(b);
                        std::fill(b.begin(), b.end(), 0);                            
                    }
                    // Append length to last block
                    append_length<int>(b, seen);

                    // Process the last block
                    process_block(b);

                    // Apply finalizer                   
                    finalizer_functor finalizer;
                    finalizer(state_);
                    // Convert digest to byte representation
                    digest_type d;
                    pack_n<endian_type, word_bits, octet_bits>(state_.data(), digest_words, d.data(), digest_bytes);
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
                typename boost::enable_if_c<length_bits && sizeof(Dummy)>::type append_length(block_type &block, length_type length) {
                    using namespace nil::crypto3::detail;
                    std::array<bool, length_bits> length_bits_array;
                    // FIXME1: message length can be more than 2^64 - 1 if we use 512-bit hash
                    bool is_greater = length_bits > 64;
                    // FIXME2: here we consider that length_bits == 2 * word_bits
                    if (is_greater)
                        for (length_type i = 0; i != word_bits; ++i)
                            length_bits_array[i] = false;                        

                    length_type tail_len = is_greater ? word_bits : length_bits;
                    for (length_type i = 0; i != tail_len; ++i)
                        length_bits_array[i + is_greater * word_bits] = length & (high_bits<length_type, length_bits>(~length_type(), 1) >> i);

                    // Append length
                    std::array<word_type, length_words> length_words_array;
                    for (std::size_t i = 0; i != length_words; ++i)
                        length_words_array[i] = 0;

                    pack<endian_type, 1, word_bits>(length_bits_array, length_words_array);
                    for (std::size_t i = length_words; i; --i) {
                        block[block_words - i] = length_words_array[length_words - i];
                    }
                }
                /*
                template<>
                void append_length<0>(block_type &block, length_type length) {
                }*/
                template<typename Dummy>
                typename boost::disable_if_c<length_bits && sizeof(Dummy)>::type append_length(block_type &block, length_type length) {
                    // No appending requested, so nothing to do
                }

                state_type state_;
            };

        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MERKLE_DAMGARD_BLOCK_HASH_HPP
//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP
#define CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

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
             * The Sponge construction builds a block hash from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             */
            template<typename Params, typename IV, typename Compressor, typename Finalizer = detail::nop_finalizer>
            class sponge_construction {
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

                template<typename Integer = std::size_t>
                inline sponge_construction &process_block(const block_type &block, Integer seen = Integer()) {
                    compressor_functor::process_block(state_, block);
                    return *this;
                }

                digest_type digest(const block_type &block = block_type(), std::size_t total_seen = std::size_t()) {
                    block_type b;
                    std::move(block.begin(), block.end(), b.begin());
                    std::size_t block_seen = total_seen % block_bits;
                    // Process block if block is full
                    if (total_seen && !block_seen)
                        process_block(b);

                    std::size_t copy_seen = block_seen;
                    // Apply finalizer
                    finalizer_functor finalizer;
                    finalizer(b, block_seen);
                    process_block(b);

                    // If block is not the last, process it
                    if (!finalizer.is_last_block()) {
                        finalizer(b, copy_seen);
                        process_block(b);
                    }

                    // Squeezing step of sponge function calculation
                    squeeze(state_);

                    // Convert digest to byte representation
                    std::array<octet_type, state_bits / octet_bits> d_full;
                    nil::crypto3::detail::pack_n<endian_type, word_bits, octet_bits>(
                        state_.data(), state_words, d_full.data(), state_bits / octet_bits);

                    digest_type d;
                    std::copy(d_full.begin(), d_full.begin() + digest_bytes, d.begin());

                    return d;
                }

                sponge_construction() {
                    reset();
                }

                void reset(state_type const &s) {
                    state_ = s;
                }

                void reset() {
                    iv_generator iv;
                    reset(iv());
                }

                state_type const &state() const {
                    return state_;
                }

                void squeeze(state_type &state) {
                    state_type temp_state;
                    std::fill(temp_state.begin(), temp_state.end(), 0);

                    block_type block_of_zeros;
                    std::fill(block_of_zeros.begin(), block_of_zeros.end(), 0);

                    std::size_t digest_blocks = digest_bits / block_bits;
                    std::size_t last_digest_bits = digest_bits % block_bits;

                    for (std::size_t i = 0; i != digest_blocks; ++i) {
                        for (std::size_t j = 0; j != block_words; ++j)
                            temp_state[i * block_words + j] = state[j];
                        process_block(block_of_zeros);
                    }

                    if (last_digest_bits) {
                        std::size_t last_digest_words =
                            last_digest_bits / word_bits + ((last_digest_bits % word_bits) ? 1 : 0);
                        for (std::size_t j = 0; j != last_digest_words; ++j)
                            temp_state[digest_blocks * block_words + j] = state[j];
                    }

                    state = temp_state;
                }

            private:
                state_type state_;
            };

        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MERKLE_DAMGARD_BLOCK_HASH_HPP

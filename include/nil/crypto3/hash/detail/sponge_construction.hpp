//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP
#define CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            /*!
             * @brief
             * @tparam DigestEndian
             * @tparam DigestBits
             *
             * The Sponge construction builds a block hashes from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             */
            template<typename Params,
                     typename Policy,
                     typename IVGenerator, // Class produsing IV
                     typename Absorber,    // Must provide void absorb(block, state)
                     typename Permutator,  // Must provide void permute(state)
                     typename Padder       // Must provide std::vector<block_type> get_padded_blocks(block)
                     >
            class sponge_construction {
            // This implementation corresponds to hash accumulator, it consumes full block rather than words.
            public:
                using endian_type = typename Params::digest_endian;

                constexpr static const std::size_t word_bits = Policy::word_bits;
                using word_type = typename Policy::word_type;

                // S = R || C (state)
                constexpr static const std::size_t state_bits = Policy::state_bits;
                constexpr static const std::size_t state_words = Policy::state_words;
                using state_type = typename Policy::state_type;

                // R (bitrate). `block` is used to fit other code (e.g. accumulator)
                constexpr static const std::size_t block_bits = Policy::block_bits;
                constexpr static const std::size_t block_words = Policy::block_words;
                using block_type = typename Policy::block_type;

                constexpr static const std::size_t digest_bits = Params::digest_bits;
                constexpr static const std::size_t digest_bytes = digest_bits / octet_bits;
                constexpr static const std::size_t digest_words = digest_bits / word_bits + (digest_bits % word_bits == 0 ? 0 : 1);
                using digest_type = static_digest<digest_bits>;

                sponge_construction() {
                    reset();
                }

                digest_type digest() {
                    using namespace nil::crypto3::detail;

                    std::array<word_type, digest_words> squeezed_blocks_holder;
                    constexpr static std::size_t blocks_needed_for_digest =  digest_bits / block_bits + (digest_bits % block_bits == 0 ? 0 : 1);
                    for (std::size_t i = 0; i < blocks_needed_for_digest; ++i) {
                        std::size_t dest_offset = i * block_words;
                        block_type squeezed = squeeze();
                        // TODO: check if this will break in case >1. sinse there could be not enough squeezed_blocks_holder
                        pack_from<endian_type, word_bits, word_bits>(
                            squeezed.begin(),
                            squeezed.begin() + std::min(squeezed.size(), squeezed_blocks_holder.size() - dest_offset),
                            squeezed_blocks_holder.begin() + dest_offset
                        );
                    }

                    std::array<octet_type, digest_bits / octet_bits> d_full;
                    pack_from<endian_type, word_bits, octet_bits>(squeezed_blocks_holder.begin(), squeezed_blocks_holder.end(), d_full.begin());

                    digest_type d;
                    std::copy(d_full.begin(), d_full.begin() + digest_bytes, d.begin());

                    return d;
                }

                void absorb(const block_type &block) {
                    Absorber::absorb(block, state_);
                    Permutator::permute(state_);
                    permutation_was_made_ = true;
                }

                void absorb_with_padding(const block_type &block = block_type(),
                                          const std::size_t last_block_bits_filled = 0) {
                    // Mb create padding somewhere else and only keep absorb(...) method?
                    auto padded_blocks = Padder::get_padded_blocks(block, last_block_bits_filled);
                    for (auto& block : padded_blocks) {
                        absorb(std::move(block));
                    }
                }

                block_type squeeze() {
                    if (!permutation_was_made_) {
                        // In hypothetical case when we don't have padding and did not absorb values before.
                        // Thus, not to return initial state, we do this permutation.
                        Permutator::permute(state_);
                        permutation_was_made_ = true;
                    }
                    block_type block;
                    std::copy(state_.begin(), state_.begin() + block_words, block.begin());
                    Permutator::permute(state_);
                    return block;
                }


                void reset(state_type const &s) {
                    state_ = s;
                    permutation_was_made_ = false;
                }

                void reset() {
                    reset(IVGenerator::generate());
                }

                state_type const &state() const {
                    return state_;
                }

            private:
                state_type state_;
                bool permutation_was_made_;
            };

            template<typename Policy,
                     typename IVGenerator, // Class produsing IV
                     typename Absorber,    // Must provide void absorb(block, state)
                     typename Permutator,  // Must provide void permute(state)
                     typename Padder       // Must provide std::vector<block_type> get_padded_blocks(block)
                     >
            class algebraic_sponge_construction {
            // This implementation corresponds to hash accumulator, it consumes full block rather than words.
            public:
                using word_type = typename Policy::word_type;

                // S = R || C (state)
                constexpr static const std::size_t state_words = Policy::state_words;
                using state_type = std::array<word_type, state_words>;

                // R (bitrate). `block` is used to fit other code (e.g. accumulator)
                constexpr static const std::size_t block_words = Policy::block_words;
                using block_type = std::array<word_type, block_words>;

                using digest_type = typename Policy::digest_type;

                algebraic_sponge_construction() {
                    reset();
                }

                digest_type digest() {
                    return squeeze()[0];
                }

                void absorb(const block_type &block) {
                    Absorber::absorb(block, state_);
                    Permutator::permute(state_);
                    permutation_was_made_ = true;
                }

                void absorb_with_padding(const block_type &block,
                                          const std::size_t last_block_words_filled = block_words) {
                    auto padded_blocks = Padder::get_padded_blocks(block, last_block_words_filled);
                    for (auto& block : padded_blocks) {
                        absorb(std::move(block));
                    }
                }

                block_type squeeze() {
                    if (!permutation_was_made_) {
                        // In case when we don't have padding and did not absorb values before.
                        // Thus, not to return initial state, we do this permutation. E.g. Poseidon,
                        // which does not use any padding.
                        Permutator::permute(state_);
                        permutation_was_made_ = true;
                    }
                    block_type block;
                    std::copy(state_.begin(), state_.begin() + block_words, block.begin());
                    Permutator::permute(state_);
                    return block;
                }

                void reset(state_type const& s) {
                    state_ = s;
                    permutation_was_made_ = false;
                }

                void reset() {
                    reset(IVGenerator::generate());
                }

                const state_type& state() const {
                    return state_;
                }

            private:
                state_type state_;
                bool permutation_was_made_;
            };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP

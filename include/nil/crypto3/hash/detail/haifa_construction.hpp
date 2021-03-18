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

#ifndef CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP
#define CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP

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
             * The HAIFA construction builds a block hashes from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             *
             * @note https://eprint.iacr.org/2007/278.pdf
             */
            template<typename Params, typename IV, typename Compressor, typename Padding,
                     typename Finalizer = detail::nop_finalizer>
            class haifa_construction {
            public:
                typedef Compressor compressor_functor;
                typedef Padding padding_functor;
                typedef Finalizer finalizer_functor;

                typedef typename Params::digest_endian endian_type;

                constexpr static const std::size_t salt_bits = compressor_functor::salt_bits;
                typedef typename compressor_functor::salt_type salt_type;
                constexpr static const salt_type salt_value = compressor_functor::salt_value;

                typedef typename compressor_functor::iv_generator iv_generator;

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
                constexpr static const std::size_t digest_words =
                    digest_bits / word_bits + ((digest_bits % word_bits) ? 1 : 0);
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
                inline haifa_construction &process_block(const block_type &block, Integer seen,
                                                         Integer finalization = 0) {
                    compressor_functor::process_block(state_, block, seen, finalization);
                    return *this;
                }

                inline digest_type digest(const block_type &block = block_type(),
                                          std::size_t total_seen = length_type()) {
                    using namespace nil::crypto3::detail;

                    block_type b = block;
                    // Process block if it is full
                    if (total_seen && !(total_seen % block_bits))
                        process_block(b, total_seen);

                    // Pad last message block
                    padding_functor padding;
                    padding(b, total_seen);

                    // Process last block
                    process_block(b, total_seen, salt_value);

                    // Apply finalizer
                    finalizer_functor()(state_);

                    // Convert digest to byte representation
                    std::array<octet_type, state_bits / octet_bits> d_full;
                    pack_from<endian_type, word_bits, octet_bits>(state_.begin(), state_.end(), d_full.begin());
                    digest_type d;
                    std::copy(d_full.begin(), d_full.begin() + digest_bytes, d.begin());

                    return d;
                }

                haifa_construction() {
                    reset();
                }

                void reset(const state_type &s) {
                    state_ = s;
                    state_[0] ^= 0x01010000U ^ (digest_bits / CHAR_BIT);
                }

                void reset() {
                    iv_generator iv;
                    reset(iv());
                }

                state_type const &state() const {
                    return state_;
                }

            private:
                state_type state_;
            };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP

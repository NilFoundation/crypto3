//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP
#define CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/inject.hpp>

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
             * The HAIFA construction builds a block hash from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             *
             * @note https://eprint.iacr.org/2007/278.pdf
             */
            template<typename Params, typename IV, typename Compressor, typename Finalizer = nop_finalizer>
            class haifa_construction {
            public:
                typedef Compressor compressor_functor;
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
                constexpr static const std::size_t digest_words = digest_bits / word_bits + ((digest_bits % word_bits) ? 1 : 0);
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
                template<typename Integer = std::size_t>
                inline haifa_construction &process_block(const block_type &block, Integer seen,
                                                         Integer finalization = 0) {
                    compressor_functor::process_block(state_, block, seen, finalization);
                    return *this;
                }

                inline digest_type end_message() {
                    digest_type d = digest();
                    reset();
                    return d;
                }

                inline digest_type digest(const block_type &block = block_type(), length_type seen = length_type()) {
                    // FIXME: this message padding works only for blake2b hash                     
                    using namespace nil::crypto3::detail;
                    block_type b;
                    length_type head_bits = seen % block_bits; // the number of significant bits in block
                    length_type head_words = (seen / word_bits) % block_words; // the number of significant block words
                        
                    std::move(block.begin(), block.end(), b.begin());
                    // Remove possible garbage from the block
                    std::fill(b.begin() + head_words + 1, b.end(), 0);
                    injector::inject(0, word_bits - (head_bits % word_bits), b, head_bits);

                    // Process the last block
                    process_block(b, seen, salt_value);

                    // Apply finalizer                   
                    finalizer_functor finalizer;
                    finalizer(state_);
                    
                    // Convert digest to byte representation
                    std::array<octet_type, state_bits / octet_bits> d_full;
                    pack_n<endian_type, word_bits, octet_bits>(state_.data(), state_words, d_full.data(), state_bits / octet_bits);

                    digest_type d;
                    for (size_t i = 0; i != digest_bytes; ++i)
                        d[i] = d_full[i];
                    
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

        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP

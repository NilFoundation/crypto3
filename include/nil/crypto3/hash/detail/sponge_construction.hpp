//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
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
             * The Merkle-Damgård construction builds a block hash from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest_type that will
             * truncate the internal state.
             */
            template<typename DigestEndian, int DigestBits, typename IV, typename Compressor,
                     typename Finalizer = nop_finalizer>
            class sponge_construction {
            public:
                typedef static_digest<DigestBits> digest_type;

                typedef IV iv_generator;
                typedef Compressor compressor_functor;
                typedef Finalizer finalizer_functor;

                constexpr static const std::size_t word_bits = compressor_functor::word_bits;
                typedef typename compressor_functor::word_type word_type;

                constexpr static const std::size_t state_bits = compressor_functor::state_bits;
                constexpr static const std::size_t state_words = compressor_functor::state_words;
                typedef typename compressor_functor::state_type state_type;

                constexpr static const std::size_t block_bits = compressor_functor::block_bits;
                constexpr static const std::size_t block_words = compressor_functor::block_words;
                typedef typename compressor_functor::block_type block_type;

                sponge_construction &operator()(block_type const &block) {
                    compressor_functor()(state_, block);
                    return *this;
                }

                template<typename DigestType = digest_type>
                DigestType end_message() {
                    DigestType d = digest();
                    reset();
                    return d;
                }

                template<typename DigestType = digest_type>
                DigestType digest() {
                    finalizer_functor finalizer;
                    finalizer(state_);
                    DigestType d;
                    ::nil::crypto3::detail::pack_n<DigestEndian, word_bits, octet_bits>(state_.data(), DigestBits / word_bits, d.data(),
                                                                DigestBits / octet_bits);
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

            private:
                state_type state_;
            };

        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MERKLE_DAMGARD_BLOCK_HASH_HPP

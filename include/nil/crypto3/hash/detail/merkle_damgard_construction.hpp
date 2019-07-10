//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP
#define CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>
#include <nil/crypto3/hash/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<typename Params>
            struct merkle_damgard_finalizer {

            };

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
             *
             * @note http://www.merkle.com/papers/Thesis1979.pdf
             */
            template<typename DigestEndian, int DigestBits,
                     typename IV,
                     typename Compressor,
                     typename Finalizer = nop_finalizer>
            class merkle_damgard_construction {
            public:
                typedef hash::static_digest<DigestBits> digest_type;

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

                merkle_damgard_construction &operator()(const block_type &block) {
                    compressor_functor()(state_, block);
                    return *this;
                }

                digest_type end_message() {
                    digest_type d = digest();
                    reset();
                    return d;
                }

                digest_type digest() {
                    finalizer_functor finalizer;
                    finalizer(state_);
                    digest_type d;
                    pack_n<DigestEndian, word_bits, octet_bits>(state_.data(), DigestBits / word_bits, d.data(),
                            DigestBits / octet_bits);
                    return d;
                }

                merkle_damgard_construction() {
                    reset();
                }

                void reset(const state_type &s) {
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

        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_MERKLE_DAMGARD_BLOCK_HASH_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_CUBEHASH_HPP
#define CRYPTO3_HASH_CUBEHASH_HPP

#include <nil/crypto3/hash/detail/cubehash_policy.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_state_preprocessor.hpp>

// Submission to NIST for SHA-3 is CubeHash16/32
// http://cubehash.cr.yp.to/submission/tweak.pdf
#ifndef CRYPTO3_HASH_CUBEHASH_DEFAULT_R
#define CRYPTO3_HASH_CUBEHASH_DEFAULT_R 16
#endif
#ifndef CRYPTO3_HASH_CUBEHASH_DEFAULT_B
#define CRYPTO3_HASH_CUBEHASH_DEFAULT_B 32
#endif

namespace nil {
    namespace crypto3 {
        namespace hash {

            template<unsigned r, unsigned b, unsigned h>
            struct cubehash_compressor {
                typedef detail::cubehash_policy<r, b, h> policy_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                inline void operator()(state_type &state, block_type const &block) {
                    process_block(state, block);
                }

            protected:
                inline static void process_block(state_type &state, const block_type &block) {
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                    printf("Xoring the following block to the state:\n");
                    for (unsigned i = 0; i < block.size(); ++i) {
                        printf("%.8x%c", block[i], (i+1) != block.size() ? ' ' : '\n');
                    }
#endif
                    for (unsigned i = 0; i < block_words; ++i) {
                        state[i] ^= block[i];
                    }
                    policy_type::transform_r(state);
                }

            };

            template<unsigned r, unsigned b, unsigned h>
            struct cubehash_finalizer {
                typedef detail::cubehash_policy<r, b, h> policy_type;
                typedef typename policy_type::state_type state_type;

                inline void operator()(state_type &state) const {
                    state[31] ^= 1;
                    policy_type::transform_10r(state);
                }
            };

//
// If the second and third parameters are unspecified (or left 0), then
// the first parameter is the number of bits in the static_digest, and
// r and b will be set to defaults.
//
// Otherwise the three parameters are r, b, and h respectively.
//
            template<unsigned, unsigned = 0, unsigned = 0>
            struct cubehash;

            /*!
             * @brief Cubehash. Cubehash 16/32 modification was a SHA-3 competitor submitted to NIST.
             *
             * @ingroup hash
             *
             * @tparam r
             * @tparam b
             * @tparam h
             */
            template<unsigned r, unsigned b, unsigned h>
            class cubehash {
                typedef detail::cubehash_policy<r, b, h> policy_type;
            public:
                typedef merkle_damgard_construction<stream_endian::little_octet_big_bit, policy_type::digest_bits,
                                                    typename policy_type::iv_generator, cubehash_compressor<r, b, h>,
                                                    cubehash_finalizer<r, b, h> > block_hash_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef block_hash_type_ block_hash_type;
#else
                struct block_hash_type : block_hash_type_ {
                };
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = 0; // No length padding
                    };

                    typedef merkle_damgard_state_preprocessor<block_hash_type, StateAccumulator, params_type> type_;

#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename block_hash_type::digest_type digest_type;
            };

            template<std::size_t h>
            struct cubehash<h, 0, 0> : cubehash<CRYPTO3_HASH_CUBEHASH_DEFAULT_R, CRYPTO3_HASH_CUBEHASH_DEFAULT_B, h> {
            };

        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_CUBEHASH_HPP

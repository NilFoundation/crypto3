//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_SHA3_HPP
#define CRYPTO3_HASH_SHA3_HPP

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/hash/detail/sponge_construction.hpp>
#include <nil/crypto3/hash/detail/block_stream_processor.hpp>
#include <nil/crypto3/hash/detail/sha3/sha3_functions.hpp>
#include <nil/crypto3/hash/detail/sha3/sha3_policy.hpp>
#include <nil/crypto3/hash/detail/sha3/sha3_finalizer.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t DigestBits = 512>
            class sha3_compressor {
            protected:
                typedef detail::sha3_functions<DigestBits> policy_functions;
                typedef detail::sha3_policy<DigestBits> policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                static void process_block(state_type &state, const block_type &block) {
                    for (std::size_t i = 0; i != block_words; ++i)
                        state[i] ^= block[i];

                    policy_functions::permute(state);
                }
            };

            /*!
             * @brief
             * @tparam DigestBits
             * @ingroup hash
             */
            template<std::size_t DigestBits = 512>
            class sha3 {
                typedef detail::sha3_policy<DigestBits> policy_type;

            public:
                struct construction {
                    struct params_type {
                        typedef typename stream_endian::big_octet_little_bit digest_endian;

                        constexpr static const std::size_t length_bits = 0;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef detail::sha3_finalizer<typename params_type::digest_endian, DigestBits>
                        sha3_finalizer;

                    typedef sponge_construction<params_type, typename policy_type::iv_generator,
                                                sha3_compressor<DigestBits>, sha3_finalizer>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::big_octet_little_bit digest_endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };
                    typedef block_stream_processor<construction, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif

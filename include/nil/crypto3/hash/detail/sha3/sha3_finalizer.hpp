//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SHA3_FINALIZER_HPP
#define CRYPTO3_SHA3_FINALIZER_HPP

#include <nil/crypto3/hash/detail/sha3/sha3_policy.hpp>

#include <boost/endian/conversion.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                class sha3_finalizer {
                    typedef PolicyType policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    constexpr static const std::size_t digest_blocks = digest_bits / block_bits;
                    constexpr static const std::size_t last_digest_bits = digest_bits % block_bits;
                    constexpr static const std::size_t last_digest_words =
                        last_digest_bits / word_bits + ((last_digest_bits % word_bits) ? 1 : 0);

                    typedef typename policy_type::digest_type digest_type;
                    typedef sha3_functions<digest_bits> policy_func_type;

                public:
                    void operator()(state_type &state) {
                        state_type temp_state;
                        std::fill(temp_state.begin(), temp_state.end(), 0);

                        for (std::size_t i = 0; i != digest_blocks; ++i) {
                            for (std::size_t j = 0; j != block_words; ++j)
                                temp_state[i * block_words + j] = state[j];

                            for (std::size_t i = 0; i != state_words; ++i)
                                boost::endian::endian_reverse_inplace(state[i]);

                            policy_func_type::permute(state);

                            for (std::size_t i = 0; i != state_words; ++i)
                                boost::endian::endian_reverse_inplace(state[i]);
                        }

                        if (last_digest_bits) {
                            for (std::size_t j = 0; j != last_digest_words; ++j)
                                temp_state[digest_blocks * block_words + j] = state[j];
                        }

                        state = temp_state;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_FINALIZER_HPP

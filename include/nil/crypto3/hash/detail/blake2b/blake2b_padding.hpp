//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLAKE2B_PADDING_HPP
#define CRYPTO3_BLAKE2B_PADDING_HPP

#include <nil/crypto3/hash/detail/blake2b/blake2b_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<typename Endianness, typename PolicyType>
                class blake2b_padding {
                    typedef PolicyType policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    typedef ::nil::crypto3::detail::injector<Endianness, word_bits, block_words, block_bits>
                        injector_type;

                public:
                    void operator()(block_type &block, word_type total_seen) {
                        // Pad block with zero bits if it is empty or incomplete
                        if (!total_seen || total_seen % block_bits) {
                            word_type seen_words =
                                ((total_seen / word_bits) % block_words) + ((total_seen % word_bits) ? 1 : 0);
                            std::fill(block.begin() + seen_words, block.end(), 0);
                            // Pad with zeros last significant word if it is incomplete
                            if (total_seen % word_bits) {
                                word_type block_seen = total_seen % block_bits;
                                injector_type::inject(word_type(), word_bits - block_seen % word_bits, block,
                                                      block_seen);
                            }
                        }
                    }
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLAKE2B_PADDING_HPP

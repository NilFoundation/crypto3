//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLAKE2B_FINALIZER_HPP
#define CRYPTO3_BLAKE2B_FINALIZER_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<typename Endianness, typename SeenType, std::size_t WordBits, std::size_t BlockBits>
                class blake2b_finalizer : public ::nil::crypto3::detail::basic_functions<WordBits> {
                    typedef ::nil::crypto3::detail::basic_functions<WordBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_words = BlockBits / WordBits;
                    typedef std::array<word_type, block_words> block_type;

                    typedef ::nil::crypto3::detail::injector<Endianness, WordBits, block_words, BlockBits>
                        injector_type;

                public:
                    void operator()(block_type &block, SeenType total_seen) {
                        // Pad block with zero bits if it is empty or incomplete
                        if (!total_seen || total_seen % BlockBits) {
                            SeenType seen_words =
                                ((total_seen / WordBits) % block_words) + ((total_seen % WordBits) ? 1 : 0);
                            std::fill(block.begin() + seen_words, block.end(), 0);
                            // Pad with zeros last significant word if it is incomplete
                            if (total_seen % WordBits) {
                                SeenType block_seen = total_seen % BlockBits;
                                injector_type::inject(word_type(), WordBits - block_seen % WordBits, block, block_seen);
                            }
                        }
                    }
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLAKE2B_FINALIZER_HPP

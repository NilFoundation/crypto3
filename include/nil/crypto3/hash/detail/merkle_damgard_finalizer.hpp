//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------////

#ifndef CRYPTO3_MERKLE_DAMGARD_FINALIZER_HPP
#define CRYPTO3_MERKLE_DAMGARD_FINALIZER_HPP

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<typename Endianness, typename PolicyType>
                class merkle_damgard_finalizer {
                    typedef PolicyType policy_type;
                    //typedef ::nil::crypto3::detail::basic_functions<WordBits> policy_type;


                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;
                
                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                    /*constexpr static const std::size_t block_words = BlockBits / WordBits;

                    typedef typename policy_type::word_type word_type;
                    typedef std::array<word_type, block_words> block_type;*/

                    typedef ::nil::crypto3::detail::injector<Endianness, word_bits, block_words, block_bits> injector;

                public:
                    void operator()(block_type &block, std::size_t &block_seen) {
                        // Remove garbage
                        block_type block_of_zeros;
                        std::size_t seen_copy = block_seen;
                        std::fill(block_of_zeros.begin(), block_of_zeros.end(), 0);
                        injector::inject(block_of_zeros, block_bits - block_seen, block, seen_copy);
                        // Get bit 1 in the endianness used by the hash
                        std::array<bool, word_bits> bit_one = {1};
                        std::array<word_type, 1> bit_one_word = {0};
                        ::nil::crypto3::detail::pack<Endianness, 1, word_bits>(bit_one, bit_one_word);
                        // Add 1 bit to block
                        injector::inject(bit_one_word[0], 1, block, block_seen);
                    }
                };
            }  // namespace detail
        }      // namespace hash
    }          // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MERKLE_DAMGARD_FINALIZER_HPP

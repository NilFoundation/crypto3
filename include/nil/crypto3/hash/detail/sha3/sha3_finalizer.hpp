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

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<typename Endianness, std::size_t DigestBits>
                class sha3_finalizer {
                    typedef sha3_policy<DigestBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    typedef typename policy_type::state_type state_type;

                    typedef ::nil::crypto3::detail::injector<Endianness, word_bits, block_words, block_bits>
                        injector_type;

                    bool is_last;

                public:

                    sha3_finalizer() : is_last(true) {}

                    bool is_last_block() const {
                        return is_last;
                    }

                    void pad_one(block_type &block, std::size_t &block_seen) {
                        // Get bit 1 in the endianness used by the hash
                        std::array<bool, word_bits> bit_one = {1};
                        std::array<word_type, 1> bit_one_word = {0};
                        ::nil::crypto3::detail::pack<Endianness, 1, word_bits>(bit_one, bit_one_word);
                        // Add 1 bit to block
                        injector_type::inject(bit_one_word[0], 1, block, block_seen);
                    }

                    void pad_zeros(block_type &block, std::size_t &block_seen, std::size_t num) {
                        block_type zeros;
                        std::fill(zeros.begin(), zeros.end(), 0);
                        injector_type::inject(zeros, num, block, block_seen);
                    }

                    void clear(block_type &block, std::size_t &block_seen) {
                        block_seen = 0;
                        std::fill(block.begin(), block.end(), 0);
                    }

                    void operator()(block_type &block, std::size_t &block_seen) {

                        if (is_last) {
                            switch(block_bits - block_seen) {
                                case 1:
                                    // pad 0; 
                                    pad_zeros(block, block_seen, 1);
                                    is_last = false;
                                    break;
                                case 2:
                                    // pad 01;
                                    pad_zeros(block, block_seen, 1);
                                    pad_one(block, block_seen); 
                                    is_last = false;
                                    break;
                                case 3:
                                    // pad 011;
                                    pad_zeros(block, block_seen, 1);
                                    pad_one(block, block_seen);
                                    pad_one(block, block_seen);
                                    is_last = false;
                                    break;
                                default:
                                    // pad 0110*1
                                    pad_zeros(block, block_seen, 1);
                                    pad_one(block, block_seen);
                                    pad_one(block, block_seen);
                                    pad_zeros(block, block_seen, block_bits - block_seen - 4);
                                    pad_one(block, block_seen);
                                    break;                            
                            }
                        }

                        else {
                            switch(block_bits - block_seen) {
                                case 1:
                                    // pad 110*1
                                    clear(block, block_seen);
                                    pad_one(block, block_seen);
                                    pad_one(block, block_seen);
                                    pad_zeros(block, block_seen, block_bits - 3);
                                    pad_one(block, block_seen);                                    
                                    break;
                                case 2:
                                    // pad 10*1
                                    clear(block, block_seen);
                                    pad_one(block, block_seen);
                                    pad_zeros(block, block_seen, block_bits - 2);
                                    pad_one(block, block_seen); 
                                    break;
                                case 3:
                                    // pad 0*1
                                    clear(block, block_seen);
                                    pad_zeros(block, block_seen, block_bits - 1);
                                    pad_one(block, block_seen); 
                                    break;                         
                            }                            
                        }
                    }

                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_FINALIZER_HPP

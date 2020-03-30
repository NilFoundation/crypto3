//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FINALIZE_HASH_HPP
#define CRYPTO3_FINALIZE_HASH_HPP

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

#include <boost/utility/enable_if.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {

                struct nop_finalizer {
                    template<typename Dummy1, typename Dummy2>
                    void operator()(Dummy1 &, Dummy2) {
                    }
                };

                template<typename Endianness, std::size_t WordBits, std::size_t BlockBits>
                struct md_finalizer : public ::nil::crypto3::detail::basic_functions<WordBits> {
                private:
                    constexpr static const std::size_t block_words = BlockBits / WordBits;

                    typedef typename ::nil::crypto3::detail::basic_functions<WordBits>::word_type word_type;
                    typedef std::array<word_type, block_words> block_type;

                    typedef ::nil::crypto3::detail::injector<Endianness, WordBits, block_words, BlockBits> injector;

                public:
                    void operator()(block_type &block, std::size_t &block_seen) {
                        // Remove garbage
                        block_type block_of_zeros;
                        std::size_t seen_copy = block_seen;
                        std::fill(block_of_zeros.begin(), block_of_zeros.end(), 0);
                        injector::inject(block_of_zeros, BlockBits - block_seen, block, seen_copy);
                        // Get bit 1 in the endianness used by the hash
                        std::array<bool, WordBits> bit_one = {1};
                        std::array<word_type, 1> bit_one_word = {0};
                        ::nil::crypto3::detail::pack<Endianness, 1, WordBits>(bit_one, bit_one_word);
                        // Add 1 bit to block
                        injector::inject(bit_one_word[0], 1, block, block_seen);
                    }
                };
                /*
                template<typename Endianness, typename SeenType, std::size_t WordBits, std::size_t BlockWords,
                        std::size_t SeenTypeBits, std::size_t LengthBits>
                struct length_adder : public ::nil::crypto3::detail::basic_functions<WordBits> {
                private:
                    constexpr static const std::size_t length_words = LengthBits / WordBits;

                    typedef typename ::nil::crypto3::detail::basic_functions<WordBits>::word_type word_type;
                    typedef std::array<word_type, BlockWords> block_type;

                public:
                    template<typename Dummy>
                    // FIXME: do something with enable_if_c error during compilation
                    static typename boost::enable_if_c<LengthBits && sizeof(Dummy)>::type append_length(block_type
                &block, SeenType total_seen) { using namespace nil::crypto3::detail;
                        // Obtain bit representation of total_seen
                        std::array<bool, LengthBits> length_bits_array;
                        length_bits_array.fill(false);
                        SeenType mask = high_bits<SeenType, SeenTypeBits>(~SeenType(), 1);

                        for (std::size_t i = LengthBits - SeenTypeBits; i != LengthBits; ++i) {
                            length_bits_array[i] = total_seen & mask;
                            mask >>= 1;
                        }
                        // Convert bit representation of total_seen to its word representation
                        std::array<word_type, length_words> length_words_array;
                        pack<Endianness, 1, WordBits>(length_bits_array, length_words_array);
                        // Add total_seen to block
                        for (std::size_t i = length_words; i; --i)
                            block[BlockWords - i] = length_words_array[length_words - i];
                    }


                    template<typename Dummy>
                    static typename boost::disable_if_c<LengthBits && sizeof(Dummy)>::type append_length(block_type
                &block, SeenType total_seen) {
                        // No appending requested, so nothing to do
                    }
                };*/

            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_FINALIZE_HASH_HPP
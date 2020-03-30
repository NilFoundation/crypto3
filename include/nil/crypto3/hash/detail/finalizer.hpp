//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_FINALIZER_HPP
#define CRYPTO3_HASH_FINALIZER_HPP

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

#include <boost/utility/enable_if.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
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
                    static typename boost::enable_if_c<LengthBits && sizeof(Dummy)>::type
                        append_length(block_type &block, SeenType total_seen) {
                        using namespace nil::crypto3::detail;
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
                    static typename boost::disable_if_c<LengthBits && sizeof(Dummy)>::type
                        append_length(block_type &block, SeenType total_seen) {
                        // No appending requested, so nothing to do
                    }
                };

            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_FINALIZE_HASH_HPP
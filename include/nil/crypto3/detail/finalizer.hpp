//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FINALIZE_HASH_HPP
#define CRYPTO3_FINALIZE_HASH_HPP

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/inject.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

                struct nop_finalizer {
                    template<typename Dummy1, typename Dummy2>
                    void operator()(Dummy1 &, Dummy2) {
                    }
                };
                
                template<typename Endianness, typename SeenType, std::size_t WordBits, std::size_t BlockBits>
                struct finalizer : public basic_functions<WordBits> {
                private:
                    constexpr static const std::size_t block_words = BlockBits / WordBits;

                    typedef typename basic_functions<WordBits>::word_type word_type;
                    typedef std::array<word_type, block_words> block_type;

                    typedef ::nil::crypto3::detail::injector<Endianness, WordBits, block_words, BlockBits> injector;

                public:
                    void operator()(block_type &block, SeenType total_seen) {
                        // Pad block with zero bits if it is empty or incomplete
                        if (total_seen == 0 || total_seen % BlockBits != 0) {
                            SeenType seen_words = ((total_seen / WordBits) % block_words) + ((total_seen % WordBits) ? 1 : 0);
                            std::fill(block.begin() + seen_words, block.end(), 0);
                            // Pad with zeros last significant word if it is incomplete
                            if (total_seen % WordBits != 0) {
                                SeenType block_seen = total_seen % BlockBits;
                                injector::inject(word_type(), WordBits - block_seen % WordBits, block, block_seen);
                            }
                        }
                    } 
                };
                    
        }        // namespace detail
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_FINALIZE_HASH_HPP
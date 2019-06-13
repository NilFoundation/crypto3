//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_DAVIES_MEYER_COMPRESSOR_HPP
#define CRYPTO3_HASH_DAVIES_MEYER_COMPRESSOR_HPP

#include <cstddef>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             *
             * @tparam BlockCipher
             * @tparam CombineFunction
             *
             * The Davies-Meyer construction turns a block cipher
             * into a one-way compression function
             *
             * http://en.wikipedia.org/wiki/One-way_compression_function#Davies-Meyer
             */
            template<typename BlockCipher, typename CombineFunction>
            struct davies_meyer_compressor {
                typedef BlockCipher block_cipher_type;

                constexpr static const std::size_t word_bits = block_cipher_type::word_bits;
                typedef typename block_cipher_type::word_type word_type;

                constexpr static const std::size_t state_bits = block_cipher_type::block_bits;
                constexpr static const std::size_t state_words = block_cipher_type::block_words;
                typedef typename block_cipher_type::block_type state_type;

                constexpr static const std::size_t block_bits = block_cipher_type::key_bits;
                constexpr static const std::size_t block_words = block_cipher_type::key_words;
                typedef typename block_cipher_type::key_type block_type;

                inline void operator()(state_type &state, const block_type &block) {
                    process_block(state, block);
                }

            protected:
                inline static void process_block(state_type &state, const block_type &block) {
                    block_cipher_type cipher(block);
                    state_type new_state = cipher.encrypt((const state_type &) state);
                    CombineFunction f;
                    f(state, new_state);
                }
            };
        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_DAVIES_MEYER_COMPRESSOR_HPP

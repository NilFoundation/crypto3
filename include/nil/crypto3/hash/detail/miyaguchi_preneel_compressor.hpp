//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MIYAGUCHI_PRENEEL_COMPRESSOR_HPP
#define CRYPTO3_MIYAGUCHI_PRENEEL_COMPRESSOR_HPP

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             *
             * @tparam BlockCipher
             * @tparam CombineFunction
             *
             * The Miyaguchi-Preneel construction turns a block cipher
             * into a one-way compression function
             *
             * https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi–Preneel
             */
            template<typename BlockCipher, typename CombineFunction, typename KeyConverterFunctor>
            struct miyaguchi_preneel_compressor {
                typedef BlockCipher block_cipher_type;

                constexpr static const std::size_t word_bits = block_cipher_type::word_bits;
                typedef typename block_cipher_type::word_type word_type;

                constexpr static const std::size_t key_bits = block_cipher_type::key_bits;
                typedef typename block_cipher_type::key_type key_type;

                constexpr static const std::size_t state_bits = block_cipher_type::block_bits;
                constexpr static const std::size_t state_words = block_cipher_type::block_words;
                typedef typename block_cipher_type::block_type state_type;

                constexpr static const std::size_t block_bits = block_cipher_type::key_bits;
                constexpr static const std::size_t block_words = block_cipher_type::key_words;
                typedef typename block_cipher_type::block_type block_type;

                inline static void process_block(state_type &state, const block_type &block) {
                    KeyConverterFunctor k;
                    key_type key = {0};
                    k(key, state);

                    block_cipher_type cipher(key);
                    state_type new_state = cipher.encrypt(block);

                    CombineFunction f;
                    f(state, new_state);
                    f(state, block);
                }
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MIYAGUCHI_PRENEEL_COMPRESSOR_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MATYAS_MEYER_OSEAS_COMPRESSOR_HPP
#define CRYPTO3_MATYAS_MEYER_OSEAS_COMPRESSOR_HPP

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             *
             * @tparam BlockCipher
             * @tparam CombineFunction
             *
             * The Matyas-Meyer-Oseas construction turns a block cipher
             * into a one-way compression function
             *
             * https://en.wikipedia.org/wiki/One-way_compression_function#Matyas–Meyer–Oseas
             */
            template<typename BlockCipher, typename CombineFunction, typename KeyConverterFunctor>
            struct matyas_meyer_oseas_compressor {
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

                void operator()(state_type &state, const block_type &block) {
                    process_block(state, block);
                }

            protected:
                static inline void process_block(state_type &state, const block_type &block) {
                    KeyConverterFunctor k;
                    key_type key = {0};
                    k(key, state);

                    block_cipher_type cipher(key);
                    state_type new_state = cipher.encrypt(block);

                    CombineFunction f;
                    f(new_state, block);
                    state = new_state;
                }
            };
        }
    }
}

#endif //CRYPTO3_MATYAS_MEYER_OSEAS_COMPRESSOR_HPP

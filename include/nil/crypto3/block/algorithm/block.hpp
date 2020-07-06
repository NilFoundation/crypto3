//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_ALGORITHM_HPP
#define CRYPTO3_BLOCK_ALGORITHM_HPP

#include <cstdint>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief
             * @tparam Cipher
             */
            template<typename Cipher>
            struct nop_padding {
                typedef std::size_t size_type;

                typedef Cipher cipher_type;

                constexpr static const size_type block_bits = cipher_type::block_bits;
                constexpr static const size_type block_words = cipher_type::block_words;
                typedef typename cipher_type::block_type block_type;
            };
        }    // namespace block

        /*!
         * @defgroup block Block Ciphers
         *
         * @brief Block ciphers are a n-bit permutation for some small ```n```,
         * typically 64 or 128 bits. It is a cryptographic primitive used
         * to generate higher level operations such as authenticated encryption.
         *
         * @defgroup block_algorithms Algorithms
         * @ingroup block
         * @brief Algorithms are meant to provide encryption interface similar to STL algorithms' one.
         */
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_AES_HPP
#define CRYPTO3_BLOCK_AES_HPP

#include <nil/crypto3/block/rijndael.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief AES block cipher. Equals to Rijndael block cipher with 128 bit block length.
             */
            template<std::size_t KeyBits>
            using aes = rijndael<KeyBits, 128>;
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_AES_HPP

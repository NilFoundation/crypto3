//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHER_HPP
#define CRYPTO3_BLOCK_CIPHER_HPP

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief
             * @tparam Cipher
             * @tparam Mode
             * @tparam Padding
             */
            template<typename Cipher, typename Mode, typename Padding>
            struct cipher : public Mode::template bind<Cipher, Padding>::type {
                typedef std::size_t size_type;

                typedef Cipher cipher_type;
                typedef Mode mode_type;
                typedef Padding padding_type;
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif

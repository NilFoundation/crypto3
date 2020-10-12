//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ALGORITHM_HPP
#define CRYPTO3_PUBKEY_ALGORITHM_HPP

#include <cstdint>

#include <nil/crypto3/pubkey/detail/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief
             * @tparam Cipher
             */
            template<typename Scheme>
            struct nop_padding {
                typedef std::size_t size_type;

                typedef Scheme scheme_type;
            };
        }    // namespace pubkey

        /*!
         * @defgroup pubkey Public Key Schemes
         *
         * @brief
         *
         * @defgroup pubkey_algorithms Algorithms
         * @ingroup pubkey
         * @brief Algorithms are meant to provide scheme operations interfaces
         * similar to STL algorithms' one.
         */
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_HPP

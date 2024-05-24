//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_CIPHERTEXT_STEALING_HPP
#define CRYPTO3_CIPHERTEXT_STEALING_HPP

#include <cstdlib>

#include <nil/crypto3/modes/mode.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                /*!
                 * @brief
                 * @tparam Version
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<std::size_t Version, typename Cipher, typename Padding>
                struct ciphertext_stealing_mode {};

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<0, Cipher, Padding> {};

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<1, Cipher, Padding> {};

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<2, Cipher, Padding> {};

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                struct ciphertext_stealing_mode<3, Cipher, Padding> {};

                /*!
                 * @brief
                 *
                 * @tparam Version
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<std::size_t Version, typename Cipher, typename Padding>
                using cts = ciphertext_stealing_mode<Version, Cipher, Padding>;

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                using cts0 = ciphertext_stealing_mode<0, Cipher, Padding>;

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                using cts1 = ciphertext_stealing_mode<1, Cipher, Padding>;

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                using cts2 = ciphertext_stealing_mode<2, Cipher, Padding>;

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, typename Padding>
                using cts3 = ciphertext_stealing_mode<3, Cipher, Padding>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHERTEXT_STEALING_HPP

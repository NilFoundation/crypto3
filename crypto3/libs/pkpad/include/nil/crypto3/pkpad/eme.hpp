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

#ifndef CRYPTO3_PUBKEY_EME_ENCRYPTION_PAD_HPP
#define CRYPTO3_PUBKEY_EME_ENCRYPTION_PAD_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                /*!
                 * @brief Encoding Method for Encryption
                 * @tparam Scheme
                 * @tparam Hash
                 */
                template<typename Scheme, typename Hash>
                struct eme {
                    typedef Scheme scheme_type;
                    typedef Hash hash_type;

                    typedef typename scheme_type::key_type key_type;
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif

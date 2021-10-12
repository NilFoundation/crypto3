//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_HPP
#define CRYPTO3_PUBKEY_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @defgroup pubkey Asymmetric cryptography
             *
             * @brief Hash functions are one-way functions, which map data of arbitrary size to a
             * fixed output length. Most of the hashes functions in crypto3 are designed to be
             * cryptographically secure, which means that it is computationally infeasible to
             * create a collision (finding two inputs with the same hashes) or preimages (given a
             * hashes output, generating an arbitrary input with the same hashes). But note that
             * not all such hashes functions meet their goals, in particular @ref nil::crypto3::hashes::md4 "MD4" and
             * @ref nil::crypto3::hashes::md5 "MD5" are trivially broken. However they are still included due to their
             * wide adoption in various protocols.
             *
             * @defgroup pubkey_algorithms Asymmetric algorithms
             * @ingroup pubkey
             * @brief Algorithms are meant to provide interface to asymmetric operations similar to STL algorithms' one.
             */
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // include guard

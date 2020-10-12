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

#ifndef CRYPTO3_STREAM_HPP
#define CRYPTO3_STREAM_HPP

namespace nil {
    namespace crypto3 {
        /*!
         * @defgroup stream Stream Ciphers
         * @brief In contrast to block ciphers, stream ciphers operate on a plaintext stream
         * instead of blocks. Thus encrypting data results in changing the internal state
         * of the cipher and encryption of plaintext with arbitrary length is possible in
         * one go (in byte amounts).
         *
         * @defgroup stream_algorithms Algorithms
         * @ingroup stream
         * @brief Algorithms are meant to provide decryption interface similar to STL algorithms' one.
         */
    }
}

#endif    // CRYPTO3_STREAM_HPP

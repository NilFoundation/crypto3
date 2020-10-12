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

#ifndef CRYPTO3_KASUMI_FUNCTIONS_CPP_HPP
#define CRYPTO3_KASUMI_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/kasumi/kasumi_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct kasumi_functions : public kasumi_policy {
                    constexpr static const std::size_t word_bits = kasumi_policy::word_bits;
                    typedef typename kasumi_policy::word_type word_type;

                    static inline word_type FI(word_type I, word_type K) {
                        word_type D9 = (I >> 7);
                        word_type D7 = (I & 0x7F);
                        D9 = s9_substitution[D9] ^ D7;
                        D7 = s7_substitution[D7] ^ (D9 & 0x7F);

                        D7 ^= (K >> 9);
                        D9 = s9_substitution[D9 ^ (K & 0x1FF)] ^ D7;
                        D7 = s7_substitution[D7] ^ (D9 & 0x7F);
                        return static_cast<word_type>(D7 << 9) | D9;
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KASUMI_FUNCTIONS_CPP_HPP

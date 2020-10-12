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

#ifndef CRYPTO3_MAC_BASIC_FUNCTIONS_HPP
#define CRYPTO3_MAC_BASIC_FUNCTIONS_HPP

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<std::size_t WordBits>
                struct basic_functions {
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t word_bits = WordBits;
                    typedef typename boost::uint_t<word_bits>::exact word_type;

                    static inline word_type shr(word_type x, std::size_t n) {
                        return x >> n;
                    }

                    template<std::size_t n>
                    static inline word_type shr(word_type x) {
                        BOOST_STATIC_ASSERT(n < word_bits);
                        return x >> n;
                    }

                    static inline word_type shl(word_type x, std::size_t n) {
                        return x << n;
                    }

                    template<std::size_t n>
                    static inline word_type shl(word_type x) {
                        BOOST_STATIC_ASSERT(n < word_bits);
                        return x << n;
                    }

                    static inline word_type rotr(word_type x, std::size_t n) {
                        return shr(x, n) | shl(x, word_bits - n);
                    }

                    template<std::size_t n>
                    static inline word_type rotr(word_type x) {
                        return shr<n>(x) | shl<word_bits - n>(x);
                    }

                    static inline word_type rotl(word_type x, std::size_t n) {
                        return shl(x, n) | shr(x, word_bits - n);
                    }

                    template<std::size_t n>
                    static inline word_type rotl(word_type x) {
                        return shl<n>(x) | shr<word_bits - n>(x);
                    }
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BASIC_FUNCTIONS_HPP

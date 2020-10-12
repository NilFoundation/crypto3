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

#ifndef CRYPTO3_BLOCK_CIPHERS_DETAIL_SHACAL_FUNCTIONS_HPP
#define CRYPTO3_BLOCK_CIPHERS_DETAIL_SHACAL_FUNCTIONS_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

                /*!
                 * @brief
                 * @tparam WordBits
                 *
                 * Implemented directly from the standard as found at
                 * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
                 * Specifically, subsection 4.1
                 */
                template<std::size_t WordBits>
                struct basic_shacal_functions : public ::nil::crypto3::detail::basic_functions<WordBits> {
                    typedef typename ::nil::crypto3::detail::basic_functions<WordBits>::word_type word_type;

                    static word_type Ch(word_type x, word_type y, word_type z) {
                        return (x & y) ^ (~x & z);
                    }

                    static word_type Maj(word_type x, word_type y, word_type z) {
                        return (x & y) ^ (x & z) ^ (y & z);
                    }
                };

                struct shacal_functions : public basic_shacal_functions<32> {
                    static word_type Parity(word_type x, word_type y, word_type z) {
                        return x ^ y ^ z;
                    }

                    static word_type f(unsigned t, word_type x, word_type y, word_type z) {
                        if (t < 40) {
                            if (t < 20) {
                                return Ch(x, y, z);
                            }
                        } else {
                            if (t < 60) {
                                return Maj(x, y, z);
                            }
                        }
                        return Parity(x, y, z);
                    }
                };

                typedef shacal_functions shacal0_functions;
                typedef shacal_functions shacal1_functions;

                template<std::size_t WordBits>
                struct shacal2_functions;

                template<>
                struct shacal2_functions<32> : public basic_shacal_functions<32> {
                    static word_type Sigma_0(word_type x) {
                        return rotr<2>(x) ^ rotr<13>(x) ^ rotr<22>(x);
                    }

                    static word_type Sigma_1(word_type x) {
                        return rotr<6>(x) ^ rotr<11>(x) ^ rotr<25>(x);
                    }

                    static word_type sigma_0(word_type x) {
                        return rotr<7>(x) ^ rotr<18>(x) ^ shr<3>(x);
                    }

                    static word_type sigma_1(word_type x) {
                        return rotr<17>(x) ^ rotr<19>(x) ^ shr<10>(x);
                    }
                };

                template<>
                struct shacal2_functions<64> : public basic_shacal_functions<64> {
                    static word_type Sigma_0(word_type x) {
                        return rotr<28>(x) ^ rotr<34>(x) ^ rotr<39>(x);
                    }

                    static word_type Sigma_1(word_type x) {
                        return rotr<14>(x) ^ rotr<18>(x) ^ rotr<41>(x);
                    }

                    static word_type sigma_0(word_type x) {
                        return rotr<1>(x) ^ rotr<8>(x) ^ shr<7>(x);
                    }

                    static word_type sigma_1(word_type x) {
                        return rotr<19>(x) ^ rotr<61>(x) ^ shr<6>(x);
                    }
                };

            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_DETAIL_SHACAL_FUNCTIONS_HPP

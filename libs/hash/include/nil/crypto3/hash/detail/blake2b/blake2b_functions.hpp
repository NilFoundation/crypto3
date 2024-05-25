//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLAKE2B_FUNCTIONS_HPP
#define CRYPTO3_BLAKE2B_FUNCTIONS_HPP

#include <array>

#include <nil/crypto3/hash/detail/blake2b/blake2b_policy.hpp>

#include <boost/static_assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits>
                struct blake2b_functions : public blake2b_policy<DigestBits> {
                    typedef blake2b_policy<DigestBits> policy_type;

                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;

                    inline static void g(word_type &a, word_type &b, word_type &c, word_type &d, word_type M0,
                                         word_type M1) {
                        a = a + b + M0;
                        d = policy_type::template rotr<32>(d ^ a);
                        c = c + d;
                        b = policy_type::template rotr<24>(b ^ c);
                        a = a + b + M1;
                        d = policy_type::template rotr<16>(d ^ a);
                        c = c + d;
                        b = policy_type::template rotr<63>(b ^ c);
                    }

                    template<size_t i0, size_t i1, size_t i2, size_t i3, size_t i4, size_t i5, size_t i6, size_t i7,
                             size_t i8, size_t i9, size_t iA, size_t iB, size_t iC, size_t iD, size_t iE, size_t iF>
                    inline static void round(std::array<word_type, state_words * 2> &v,
                                             const std::array<word_type, state_words * 2> &M) {
                        g(v[0], v[4], v[8], v[12], M[i0], M[i1]);
                        g(v[1], v[5], v[9], v[13], M[i2], M[i3]);
                        g(v[2], v[6], v[10], v[14], M[i4], M[i5]);
                        g(v[3], v[7], v[11], v[15], M[i6], M[i7]);
                        g(v[0], v[5], v[10], v[15], M[i8], M[i9]);
                        g(v[1], v[6], v[11], v[12], M[iA], M[iB]);
                        g(v[2], v[7], v[8], v[13], M[iC], M[iD]);
                        g(v[3], v[4], v[9], v[14], M[iE], M[iF]);
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLAKE2B_FUNCTIONS_HPP

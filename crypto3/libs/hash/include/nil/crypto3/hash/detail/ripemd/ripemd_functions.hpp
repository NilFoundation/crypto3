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

#ifndef CRYPTO3_RIPEMD_FUNCTIONS_HPP
#define CRYPTO3_RIPEMD_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/ripemd/ripemd_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits>
                struct ripemd_functions : public ripemd_policy<DigestBits> {
                    typedef ripemd_policy<DigestBits> policy_type;

                    typedef typename policy_type::word_type word_type;

                    struct f1 {
                        inline word_type operator()(word_type x, word_type y, word_type z) const {
                            return x ^ y ^ z;
                        }
                    };

                    struct f2 {
                        inline word_type operator()(word_type x, word_type y, word_type z) const {
                            return (x & y) | (~x & z);
                        }
                    };

                    struct f3 {
                        inline word_type operator()(word_type x, word_type y, word_type z) const {
                            return (x | ~y) ^ z;
                        }
                    };

                    struct f4 {
                        inline word_type operator()(word_type x, word_type y, word_type z) const {
                            return (x & z) | (y & ~z);
                        }
                    };

                    struct f5 {
                        inline word_type operator()(word_type x, word_type y, word_type z) const {
                            return x ^ (y | ~z);
                        }
                    };

                    template<typename F>
                    inline static void transform(word_type &a, word_type &b, word_type &c, word_type &d, word_type x,
                                                 word_type k, word_type s) {
                        word_type T = policy_type::rotl(a + F()(b, c, d) + x + k, s);
                        a = d;
                        d = c;
                        c = b;
                        b = T;
                    }

                    template<typename Functor>
                    inline static void transform(word_type &a, word_type &b, word_type &c, word_type &d, word_type &e,
                                                 word_type x, word_type k, word_type s) {
                        word_type T = policy_type::rotl(a + Functor()(b, c, d) + x + k, s) + e;
                        a = e;
                        e = d;
                        d = policy_type::template rotl<10>(c);
                        c = b;
                        b = T;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RIPEMD_FUNCTIONS_HPP

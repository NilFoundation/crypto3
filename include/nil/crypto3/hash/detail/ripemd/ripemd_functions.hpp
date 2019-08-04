//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RIPEMD_FUNCTIONS_HPP
#define CRYPTO3_RIPEMD_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t WordBits>
                struct ripemd_functions : public basic_functions<WordBits> {
                    constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                    typedef typename basic_functions<WordBits>::word_type word_type;

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

                    template<class F>
                    inline static void transform(word_type &a, word_type &b, word_type &c, word_type &d, word_type x,
                                                 word_type k, word_type s) {
                        word_type T = basic_functions<WordBits>::rotl(a + F()(b, c, d) + x + k, s);
                        a = d;
                        d = c;
                        c = b;
                        b = T;
                    }

                    template<typename Functor>
                    inline static void transform(word_type &a, word_type &b, word_type &c, word_type &d, word_type &e,
                                                 word_type x, word_type k, word_type s) {
                        word_type T = basic_functions<WordBits>::rotl(a + Functor()(b, c, d) + x + k, s) + e;
                        a = e;
                        e = d;
                        d = basic_functions<WordBits>::template rotl<10>(c);
                        c = b;
                        b = T;
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_RIPEMD_FUNCTIONS_HPP

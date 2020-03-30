//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM3_FUNCTIONS_HPP
#define CRYPTO3_SM3_FUNCTIONS_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                struct sm3_functions : public ::nil::crypto3::detail::basic_functions<32> {
                    constexpr static const std::size_t word_bits = ::nil::crypto3::detail::basic_functions<32>::word_bits;
                    typedef typename ::nil::crypto3::detail::basic_functions<32>::word_type word_type;

                    inline static word_type p0(word_type X) {
                        return X ^ rotl<9>(X) ^ rotl<17>(X);
                    }

                    inline static word_type ff1(word_type X, word_type Y, word_type Z) {
                        return (X & Y) | ((X | Y) & Z);
                        //return (X & Y) | (X & Z) | (Y & Z);
                    }

                    inline static word_type gg1(word_type X, word_type Y, word_type Z) {
                        //return (X & Y) | (~X & Z);
                        return ((Z ^ (X & (Y ^ Z))));
                    }

                    inline static void r1(word_type A, word_type &B, word_type C, word_type &D, word_type E,
                                          word_type &F, word_type G, word_type &H, word_type TJ, word_type Wi,
                                          word_type Wj) {
                        const word_type A12 = rotl<12>(A);
                        const word_type SS1 = rotl<7>(A12 + E + TJ);
                        const word_type TT1 = (A ^ B ^ C) + D + (SS1 ^ A12) + Wj;
                        const word_type TT2 = (E ^ F ^ G) + H + SS1 + Wi;

                        B = rotl<9>(B);
                        D = TT1;
                        F = rotl<19>(F);
                        H = p0(TT2);
                    }

                    inline static void r2(word_type A, word_type &B, word_type C, word_type &D, word_type E,
                                          word_type &F, word_type G, word_type &H, word_type TJ, word_type Wi,
                                          word_type Wj) {
                        const word_type A12 = rotl<12>(A);
                        const word_type SS1 = rotl<7>(A12 + E + TJ);
                        const word_type TT1 = ff1(A, B, C) + D + (SS1 ^ A12) + Wj;
                        const word_type TT2 = gg1(E, F, G) + H + SS1 + Wi;

                        B = rotl<9>(B);
                        D = TT1;
                        F = rotl<19>(F);
                        H = p0(TT2);
                    }

                    inline static word_type p1(word_type X) {
                        return X ^ rotl<15>(X) ^ rotl<23>(X);
                    }

                    inline static word_type sm3_e(word_type W0, word_type W7, word_type W13, word_type W3,
                                                  word_type W10) {
                        return p1(W0 ^ W7 ^ rotl<15>(W13)) ^ rotl<7>(W3) ^ W10;
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_SM3_FUNCTIONS_HPP

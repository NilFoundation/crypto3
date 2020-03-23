//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_NOEKEON_FUNCTIONS_CPP_HPP
#define CRYPTO3_NOEKEON_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct noekeon_functions : public basic_functions<WordBits> {
                    typedef typename basic_functions<WordBits>::word_type word_type;

                    /*
                     * Noekeon's Theta Operation
                     */
                    inline static void theta(word_type &A0, word_type &A1, word_type &A2, word_type &A3,
                                             const word_type *EK) {
                        word_type T = A0 ^ A2;
                        T ^= basic_functions<WordBits>::template rotl<8>(T) ^
                             basic_functions<WordBits>::template rotr<8>(T);
                        A1 ^= T;
                        A3 ^= T;

                        A0 ^= EK[0];
                        A1 ^= EK[1];
                        A2 ^= EK[2];
                        A3 ^= EK[3];

                        T = A1 ^ A3;
                        T ^= basic_functions<WordBits>::template rotl<8>(T) ^
                             basic_functions<WordBits>::template rotr<8>(T);
                        A0 ^= T;
                        A2 ^= T;
                    }

                    /*
                     * Theta With Null Key
                     */
                    inline static void theta(word_type &A0, word_type &A1, word_type &A2, word_type &A3) {
                        word_type T = A0 ^ A2;
                        T ^= basic_functions<WordBits>::template rotl<8>(T) ^
                             basic_functions<WordBits>::template rotr<8>(T);
                        A1 ^= T;
                        A3 ^= T;

                        T = A1 ^ A3;
                        T ^= basic_functions<WordBits>::template rotl<8>(T) ^
                             basic_functions<WordBits>::template rotr<8>(T);
                        A0 ^= T;
                        A2 ^= T;
                    }

                    /*
                     * Noekeon's Gamma S-Box Layer
                     */
                    inline static void gamma(word_type &A0, word_type &A1, word_type &A2, word_type &A3) {
                        A1 ^= ~A3 & ~A2;
                        A0 ^= A2 & A1;

                        word_type T = A3;
                        A3 = A0;
                        A0 = T;

                        A2 ^= A0 ^ A1 ^ A3;

                        A1 ^= ~A3 & ~A2;
                        A0 ^= A2 & A1;
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_NOEKEON_FUNCTIONS_CPP_HPP

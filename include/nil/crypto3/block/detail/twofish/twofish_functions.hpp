//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TWOFISH_FUNCTIONS_CPP_HPP
#define CRYPTO3_TWOFISH_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/twofish/basic_twofish_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t KeyBits>
                struct twofish_functions : public basic_twofish_policy<KeyBits> {
                    typedef typename basic_twofish_policy<KeyBits>::word_type word_type;

                    typedef typename basic_twofish_policy<
                            KeyBits>::expanded_substitution_type expanded_substitution_type;

                    inline static void tf_e(word_type A, word_type B, word_type &C, word_type &D, word_type RK1,
                                            word_type RK2, const expanded_substitution_type &SB) {
                        word_type X = SB[get_byte(3, A)] ^SB[256 + get_byte(2, A)] ^SB[512 + get_byte(1, A)] ^
                                      SB[768 + get_byte(0, A)];
                        word_type Y = SB[get_byte(0, B)] ^SB[256 + get_byte(3, B)] ^SB[512 + get_byte(2, B)] ^
                                      SB[768 + get_byte(1, B)];

                        X += Y;
                        Y += X;

                        X += RK1;
                        Y += RK2;

                        C = rotr<1>(C ^ X);
                        D = rotl<1>(D) ^ Y;
                    }

                    inline static void tf_d(word_type A, word_type B, word_type &C, word_type &D, word_type RK1,
                                            word_type RK2, const expanded_substitution_type &SB) {
                        word_type X = SB[get_byte(3, A)] ^SB[256 + get_byte(2, A)] ^SB[512 + get_byte(1, A)] ^
                                      SB[768 + get_byte(0, A)];
                        word_type Y = SB[get_byte(0, B)] ^SB[256 + get_byte(3, B)] ^SB[512 + get_byte(2, B)] ^
                                      SB[768 + get_byte(1, B)];

                        X += Y;
                        Y += X;

                        X += RK1;
                        Y += RK2;

                        C = rotl<1>(C) ^ X;
                        D = rotr<1>(D ^ Y);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_MISTY1_FUNCTIONS_CPP_HPP

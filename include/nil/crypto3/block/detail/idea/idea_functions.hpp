//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_IDEA_FUNCTIONS_CPP_HPP
#define CRYPTO3_IDEA_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

#include <nil/crypto3/utilities/ct_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct idea_functions : public basic_functions<WordBits> {
                    typedef typename basic_functions<WordBits>::word_type word_type;

                    /*
                     * Multiplication modulo 65537
                     */
                    static inline word_type mul(word_type x, word_type y) {
                        const uint32_t P = static_cast<uint32_t>(x) * y;

                        const word_type Z_mask = static_cast<uint16_t>(ct::expand_mask(P) & 0xFFFF);

                        const uint32_t P_hi = P >> 16;
                        const uint32_t P_lo = P & 0xFFFF;

                        const word_type carry = (P_lo < P_hi);
                        const word_type r_1 = static_cast<uint16_t>((P_lo - P_hi) + carry);
                        const word_type r_2 = 1 - x - y;

                        return ct::select(Z_mask, r_1, r_2);
                    }

                    /*
                     * Find multiplicative inverses modulo 65537
                     *
                     * 65537 is prime; thus Fermat's little theorem tells us that
                     * x^65537 == x modulo 65537, which means
                     * x^(65537-2) == x^-1 modulo 65537 since
                     * x^(65537-2) * x == 1 mod 65537
                     *
                     * Do the exponentiation with a basic square and multiply: all bits are
                     * of exponent are 1 so we always multiply
                     */
                    static inline word_type mul_inv(word_type x) {
                        word_type y = x;

                        for (size_t i = 0; i != 15; ++i) {
                            y = mul(y, y); // square
                            y = mul(y, x);
                        }

                        return y;
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_IDEA_FUNCTIONS_CPP_HPP

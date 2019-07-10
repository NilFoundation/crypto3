//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM3_POLICY_HPP
#define CRYPTO3_SM3_POLICY_HPP

#include <nil/crypto3/hash/detail/sm3/sm3_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                struct sm3_policy : public sm3_functions {
                    constexpr static const std::size_t word_bits = sm3_functions::word_bits;
                    typedef typename sm3_functions::word_type word_type;

                    constexpr static const std::size_t block_words = 8;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    constexpr static const std::size_t digest_bits = block_bits;
                    typedef static_digest<digest_bits> digest_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {{
                                                                            0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL, 0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL
                                                                    }};
                            return H0;
                        }
                    };
                };
            }
        }
    }
}

#endif //CRYPTO3_SM3_POLICY_HPP

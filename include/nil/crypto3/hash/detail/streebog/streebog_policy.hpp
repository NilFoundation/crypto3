//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_POLICY_HPP
#define CRYPTO3_STREEBOG_POLICY_HPP

#include <nil/crypto3/hash/detail/streebog/streebog_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct streebog_policy : public streebog_functions<DigestBits> {
                    constexpr static const std::size_t digest_bits = DigestBits;
                    typedef static_digest<DigestBits> digest_type;

                    constexpr static const std::size_t state_bits = streebog_functions<DigestBits>::state_bits;
                    constexpr static const std::size_t state_words = streebog_functions<DigestBits>::state_words;
                    typedef typename streebog_functions<DigestBits>::state_type state_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {{
                                                                            0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101, 0x0101010101010101
                                                                    }};
                            return H0;
                        }
                    };
                };
            }
        }
    }
}

#endif //CRYPTO3_STREEBOG_POLICY_HPP

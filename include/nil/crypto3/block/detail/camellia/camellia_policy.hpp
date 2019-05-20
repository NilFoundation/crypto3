//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CAMELLIA_POLICY_HPP
#define CRYPTO3_CAMELLIA_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/camellia/camellia_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

                template<std::size_t KeyBits>
                struct camellia_policy;

                template<>
                struct camellia_policy<128> : public camellia_functions<128> {
                    constexpr static const std::size_t rounds = 18;

                    constexpr static const std::size_t key_schedule_words = 26;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_words / word_bits;

                    typedef typename std::array<word_type, key_schedule_words> key_schedule_type;
                };

                template<>
                struct camellia_policy<192> : public camellia_functions<192> {
                    constexpr static const std::size_t rounds = 24;

                    constexpr static const std::size_t key_schedule_words = 34;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_words / word_bits;

                    typedef typename std::array<word_type, key_schedule_words> key_schedule_type;
                };

                template<>
                struct camellia_policy<256> : public camellia_functions<256> {
                    constexpr static const std::size_t rounds = 24;

                    constexpr static const std::size_t key_schedule_words = 34;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_words / word_bits;

                    typedef typename std::array<word_type, key_schedule_words> key_schedule_type;
                };
            }
        }
    }
}

#endif //CRYPTO3_CAMELLIA_POLICY_HPP

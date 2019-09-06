//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <nil/crypto3/stream/detail/chacha_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t Rounds, std::size_t IVBits, std::size_t KeyBits,
                         template<typename> class Allocator = std::allocator>
                constexpr typename chacha_policy<Rounds, IVBits, KeyBits>::round_constants_type const
                    chacha_policy<Rounds, IVBits, KeyBits>::sigma;

                template<std::size_t Rounds, std::size_t IVBits, std::size_t KeyBits,
                         template<typename> class Allocator = std::allocator>
                constexpr typename chacha_policy<Rounds, IVBits, KeyBits>::round_constants_type const
                    chacha_policy<Rounds, IVBits, KeyBits>::tau;
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

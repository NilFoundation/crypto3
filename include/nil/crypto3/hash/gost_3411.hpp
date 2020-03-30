//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_GOST_3411_HPP
#define CRYPTO3_GOST_3411_HPP

#include <nil/crypto3/hash/detail/gost_3411_policy.hpp>

#include <nil/crypto3/block/gost28147.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            class gost_3411_compressor {
                typedef detail::gost_3411_policy policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                void operator()(state_type &state, const block_type &block) {
                }
            };

            /*!
             * @brief
             * @tparam ParamsType
             * @ingroup hash
             */
            template<typename ParamsType = block::cbr_params>
            class gost_3411 {
                typedef detail::gost_3411_policy policy_type;
                typedef block::gost_28147_89<ParamsType> block_cipher_type;

            public:
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif

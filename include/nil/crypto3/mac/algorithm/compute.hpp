//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_COMPUTE_HPP
#define CRYPTO3_MAC_COMPUTE_HPP

#include <nil/crypto3/mac/algorithm/mac.hpp>

#include <nil/crypto3/mac/mac_value.hpp>
#include <nil/crypto3/mac/mac_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief
             *
             * @tparam MessageAuthenticationCode
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             * @return
             */
            template<typename MessageAuthenticationCode, typename InputIterator, typename OutputIterator>
            OutputIterator compute(InputIterator first, InputIterator last, OutputIterator out) {
            }

            /*!
             * @brief
             *
             * @tparam MessageAuthenticationCode
             * @tparam SinglePassRange
             * @tparam OutputIterator
             *
             * @param rng
             * @param out
             * @return
             */
            template<typename MessageAuthenticationCode, typename SinglePassRange, typename OutputIterator>
            OutputIterator compute(const SinglePassRange &rng, OutputIterator out) {
            }

            /*!
             * @brief
             * @tparam MessageAuthenticationCode
             * @tparam OutputRange
             * @tparam SinglePassRange
             * @param rng
             * @return
             */
            template<typename MessageAuthenticationCode, typename OutputRange, typename SinglePassRange>
            OutputRange compute(const SinglePassRange &rng) {
            }
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_COMPUTE_HPP

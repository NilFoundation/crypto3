//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
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

//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PK_PAD_SCHEME_STATE_HPP
#define CRYPTO3_PK_PAD_SCHEME_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/pkpad/accumulators/encode.hpp>
#include <nil/crypto3/pkpad/accumulators/verify.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                /*!
                 * @brief Accumulator set with pre-defined signing accumulator params.
                 *
                 * Meets the requirements of AccumulatorSet
                 *
                 * @ingroup pubkey_padding
                 *
                 * @tparam EncodingPolicy
                 */
                template<typename Padding>
                using encoding_accumulator_set = boost::accumulators::accumulator_set<
                    typename Padding::encoding_policy::result_type,
                    boost::accumulators::features<accumulators::tag::encode<typename Padding::encoding_policy>>>;

                /*!
                 * @brief Accumulator set with pre-defined signing accumulator params.
                 *
                 * Meets the requirements of AccumulatorSet
                 *
                 * @ingroup pubkey_padding
                 *
                 * @tparam VerificationPolicy
                 */
                template<typename Padding>
                using verification_accumulator_set = boost::accumulators::accumulator_set<
                    typename Padding::verification_policy::result_type,
                    boost::accumulators::features<accumulators::tag::verify<typename Padding::verification_policy>>>;
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SCHEME_STATE_HPP

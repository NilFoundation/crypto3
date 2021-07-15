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

#ifndef CRYPTO3_PUBKEY_PADDING_ENCODE_HPP
#define CRYPTO3_PUBKEY_PADDING_ENCODE_HPP

#include <nil/crypto3/pkpad/scheme_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Scheme>
                using encoding_policy = typename Scheme::encoding_policy;
            }
            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Scheme
             * @tparam InputIterator
             *
             * @param first
             * @param last
             *
             * @return
             */
            template<typename Scheme, typename InputIterator>
            typename Scheme::msg_repr_type encode(InputIterator first, InputIterator last) {
                typedef padding::encoding_policy<Scheme> EncodingPolicy;
                typedef padding::encoding_accumulator_set<EncodingPolicy> SchemeAccumulator;

                SchemeAccumulator acc;
                acc(first, accumulators::iterator_last = last);
                return accumulators::extract::encode<EncodingPolicy, SchemeAccumulator>(acc);
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Scheme
             * @tparam SinglePassRange
             *
             * @param rng
             *
             * @return
             */
            template<typename Scheme, typename SinglePassRange>
            typename Scheme::msg_repr_type encode(const SinglePassRange &rng) {
                typedef padding::encoding_policy<Scheme> EncodingPolicy;
                typedef padding::encoding_accumulator_set<EncodingPolicy> SchemeAccumulator;

                SchemeAccumulator acc;
                acc(rng);
                return accumulators::extract::encode<EncodingPolicy, SchemeAccumulator>(acc);
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Scheme
             * @tparam InputIterator
             * @tparam EncodingPolicy
             * @tparam OutputAccumulator
             *
             * @param first
             * @param last
             * @param acc
             *
             * @return
             */
            template<typename Scheme, typename InputIterator,
                     typename EncodingPolicy = padding::encoding_policy<Scheme>,
                     typename OutputAccumulator = padding::encoding_accumulator_set<EncodingPolicy>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                    OutputAccumulator>::type &
                encode(InputIterator first, InputIterator last, OutputAccumulator &acc) {
                acc(first, accumulators::iterator_last = last);
                return acc;
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Scheme
             * @tparam SinglePassRange
             * @tparam EncodingPolicy
             * @tparam OutputAccumulator
             *
             * @param r
             * @param acc
             *
             * @return
             */
            template<typename Scheme, typename SinglePassRange,
                     typename EncodingPolicy = padding::encoding_policy<Scheme>,
                     typename OutputAccumulator = padding::encoding_accumulator_set<EncodingPolicy>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                    OutputAccumulator>::type &
                encode(const SinglePassRange &r, OutputAccumulator &acc) {
                acc(r);
                return acc;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // include guard
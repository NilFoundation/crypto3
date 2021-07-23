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

#ifndef CRYPTO3_PK_PAD_VERIFY_HPP
#define CRYPTO3_PK_PAD_VERIFY_HPP

#include <nil/crypto3/pkpad/padding_state.hpp>
#include <nil/crypto3/pkpad/padding_value.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                template<typename Padding>
                using verification_policy = typename Padding::verification_policy;
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Padding
             * @tparam InputIterator
             *
             * @param first
             * @param last
             *
             * @return
             */
            template<typename Padding, typename InputIterator,
                     typename PaddingAccumulator = padding::verification_accumulator_set<Padding>,
                     typename StreamPaddingImpl = padding::detail::value_padding_impl<PaddingAccumulator>,
                     typename PaddingImpl = padding::detail::range_padding_impl<StreamPaddingImpl>>
            PaddingImpl verify(InputIterator first, InputIterator last, typename Padding::msg_repr_type &msg_repr) {
                return PaddingImpl(first, last, PaddingAccumulator(msg_repr));
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Padding
             * @tparam SinglePassRange
             *
             * @param rng
             *
             * @return
             */
            template<typename Padding, typename SinglePassRange,
                     typename PaddingAccumulator = padding::verification_accumulator_set<Padding>,
                     typename StreamPaddingImpl = padding::detail::value_padding_impl<PaddingAccumulator>,
                     typename PaddingImpl = padding::detail::range_padding_impl<StreamPaddingImpl>>
            PaddingImpl verify(const SinglePassRange &rng, typename Padding::msg_repr_type &msg_repr) {
                return PaddingImpl(rng, PaddingAccumulator(msg_repr));
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Padding
             * @tparam InputIterator
             * @tparam VerificationPolicy
             * @tparam OutputAccumulator
             *
             * @param first
             * @param last
             * @param acc
             *
             * @return
             */
            template<typename Padding, typename InputIterator,
                     typename OutputAccumulator = padding::verification_accumulator_set<Padding>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                    OutputAccumulator>::type &
                verify(InputIterator first, InputIterator last, OutputAccumulator &acc) {
                typedef padding::detail::ref_padding_impl<OutputAccumulator> StreamPaddingImpl;
                typedef padding::detail::range_padding_impl<StreamPaddingImpl> PaddingImpl;

                return PaddingImpl(first, last, std::forward<OutputAccumulator>(acc));
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Padding
             * @tparam SinglePassRange
             * @tparam VerificationPolicy
             * @tparam OutputAccumulator
             *
             * @param r
             * @param acc
             *
             * @return
             */
            template<typename Padding, typename SinglePassRange,
                     typename OutputAccumulator = padding::verification_accumulator_set<Padding>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                    OutputAccumulator>::type &
                verify(const SinglePassRange &r, OutputAccumulator &acc) {
                typedef padding::detail::ref_padding_impl<OutputAccumulator> StreamPaddingImpl;
                typedef padding::detail::range_padding_impl<StreamPaddingImpl> PaddingImpl;

                return PaddingImpl(r, std::forward<OutputAccumulator>(acc));
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Padding
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename Padding, typename InputIterator, typename OutputIterator>
            OutputIterator verify(InputIterator first, InputIterator last, OutputIterator out,
                                  typename Padding::msg_repr_type &msg_repr) {
                typedef padding::verification_accumulator_set<Padding> PaddingAccumulator;

                typedef padding::detail::value_padding_impl<PaddingAccumulator> StreamPaddingImpl;
                typedef padding::detail::itr_padding_impl<StreamPaddingImpl, OutputIterator> PaddingImpl;

                return PaddingImpl(first, last, std::move(out), PaddingAccumulator(msg_repr));
            }

            /*!
             * @brief
             *
             * @ingroup pubkey_padding_algorithms
             *
             * @tparam Padding
             * @tparam SinglePassRange
             * @tparam OutputIterator
             *
             * @param rng
             * @param out
             *
             * @return
             */
            template<typename Padding, typename SinglePassRange, typename OutputIterator>
            OutputIterator verify(const SinglePassRange &rng, OutputIterator out,
                                  typename Padding::msg_repr_type &msg_repr) {
                typedef padding::verification_accumulator_set<Padding> PaddingAccumulator;

                typedef padding::detail::value_padding_impl<PaddingAccumulator> StreamPaddingImpl;
                typedef padding::detail::itr_padding_impl<StreamPaddingImpl, OutputIterator> PaddingImpl;

                return PaddingImpl(rng, std::move(out), PaddingAccumulator(msg_repr));
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // include guard
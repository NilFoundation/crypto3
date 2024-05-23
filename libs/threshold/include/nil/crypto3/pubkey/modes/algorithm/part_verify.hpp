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

#ifndef CRYPTO3_PUBKEY_MODES_PART_VERIFY_HPP
#define CRYPTO3_PUBKEY_MODES_PART_VERIFY_HPP

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/modes/pubkey_state.hpp>

#include <nil/crypto3/pubkey/modes/part_public_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Mode>
            using part_verification_mode_policy = typename Mode::part_verification_policy;
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename Mode, typename SinglePassRange, typename OutputIterator>
        OutputIterator part_verify(
            const SinglePassRange &rng,
            const typename pubkey::part_public_key<typename Mode::scheme_type>::part_signature_type &part_sig,
            const pubkey::part_public_key<typename Mode::scheme_type> &key, OutputIterator out) {

            typedef typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type ProcessingMode;
            typedef typename pubkey::part_verification_accumulator_set<ProcessingMode> ModeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<ModeAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamVerifyerImpl, OutputIterator> VerifyerImpl;

            return VerifyerImpl(rng, std::move(out),
                                ModeAccumulator(key, nil::crypto3::accumulators::signature = part_sig));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key
         * @param out
         *
         * @return
         */
        template<typename Mode, typename InputIterator, typename OutputIterator>
        OutputIterator part_verify(
            InputIterator first, InputIterator last,
            const typename pubkey::part_public_key<typename Mode::scheme_type>::part_signature_type &part_sig,
            const pubkey::part_public_key<typename Mode::scheme_type> &key, OutputIterator out) {

            typedef typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type ProcessingMode;
            typedef typename pubkey::part_verification_accumulator_set<ProcessingMode> ModeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<ModeAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamVerifyerImpl, OutputIterator> VerifyerImpl;

            return VerifyerImpl(first, last, std::move(out),
                                ModeAccumulator(key, nil::crypto3::accumulators::signature = part_sig));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename Mode, typename InputIterator,
                 typename OutputAccumulator = typename pubkey::part_verification_accumulator_set<
                     typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            part_verify(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamVerifyerImpl> VerifyerImpl;

            return VerifyerImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */

        template<typename Mode, typename SinglePassRange,
                 typename OutputAccumulator = typename pubkey::part_verification_accumulator_set<
                     typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            part_verify(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamVerifyerImpl> VerifyerImpl;

            return VerifyerImpl(r, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam ModeAccumulator
         *
         * @param first
         * @param last
         * @param key
         *
         * @return
         */
        template<typename Mode, typename InputIterator,
                 typename ModeAccumulator = typename pubkey::part_verification_accumulator_set<
                     typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<ModeAccumulator>> part_verify(
            InputIterator first, InputIterator last,
            const typename pubkey::part_public_key<typename Mode::scheme_type>::part_signature_type &part_sig,
            const pubkey::part_public_key<typename Mode::scheme_type> &key) {

            typedef typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type ProcessingMode;

            typedef pubkey::detail::value_pubkey_impl<ModeAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamVerifyerImpl> VerifyerImpl;

            return VerifyerImpl(first, last, ModeAccumulator(key, nil::crypto3::accumulators::signature = part_sig));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam ModeAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */
        template<typename Mode, typename SinglePassRange,
                 typename ModeAccumulator = typename pubkey::part_verification_accumulator_set<
                     typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<ModeAccumulator>> part_verify(
            const SinglePassRange &r,
            const typename pubkey::part_public_key<typename Mode::scheme_type>::part_signature_type &part_sig,
            const pubkey::part_public_key<typename Mode::scheme_type> &key) {

            typedef typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type ProcessingMode;

            typedef pubkey::detail::value_pubkey_impl<ModeAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamVerifyerImpl> VerifyerImpl;

            return VerifyerImpl(r, ModeAccumulator(key, nil::crypto3::accumulators::signature = part_sig));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam ModeAccumulator
         *
         * @param first
         * @param last
         * @param key
         *
         * @return
         */
        template<typename Mode, typename InputIterator, typename Weights,
                 typename ModeAccumulator = typename pubkey::part_verification_accumulator_set<
                     typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<ModeAccumulator>> part_verify(
            InputIterator first, InputIterator last,
            const typename pubkey::part_public_key<typename Mode::scheme_type>::part_signature_type &part_sig,
            const Weights &weights, const pubkey::part_public_key<typename Mode::scheme_type> &key) {

            typedef typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type ProcessingMode;

            typedef pubkey::detail::value_pubkey_impl<ModeAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamVerifyerImpl> VerifyerImpl;

            return VerifyerImpl(first, last,
                                ModeAccumulator(key, nil::crypto3::accumulators::signature = part_sig,
                                                nil::crypto3::accumulators::weights = weights));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam ModeAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */
        template<typename Mode, typename SinglePassRange, typename Weights,
                 typename ModeAccumulator = typename pubkey::part_verification_accumulator_set<
                     typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<ModeAccumulator>> part_verify(
            const SinglePassRange &r,
            const typename pubkey::part_public_key<typename Mode::scheme_type>::part_signature_type &part_sig,
            const Weights &weights,
            const pubkey::part_public_key<typename Mode::scheme_type> &key) {

            typedef typename Mode::template bind<pubkey::part_verification_mode_policy<Mode>>::type ProcessingMode;

            typedef pubkey::detail::value_pubkey_impl<ModeAccumulator> StreamVerifyerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamVerifyerImpl> VerifyerImpl;

            return VerifyerImpl(r, ModeAccumulator(key, nil::crypto3::accumulators::signature = part_sig,
                                                   nil::crypto3::accumulators::weights = weights));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
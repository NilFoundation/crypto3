//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_MODES_SIGN_HPP
#define CRYPTO3_PUBKEY_MODES_SIGN_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/scheme_value.hpp>
#include <nil/crypto3/pubkey/modes/scheme_state.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Mode>
            using signing_mode_policy = typename Mode::signing_policy;
        }
        // /*!
        //  * @brief
        //  *
        //  * @ingroup pubkey_algorithms
        //  *
        //  * @tparam Scheme
        //  * @tparam InputIterator
        //  * @tparam KeyIterator
        //  * @tparam OutputIterator
        //  *
        //  * @param first
        //  * @param last
        //  * @param key_first
        //  * @param key_last
        //  * @param out
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename InputIterator, typename KeyInputIterator, typename OutputIterator>
        // OutputIterator sign(InputIterator first, InputIterator last, KeyInputIterator key_first,
        //                     KeyInputIterator key_last, OutputIterator out) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //     typedef typename pubkey::accumulator_set<SigningMode> ModeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;
        //
        //     return SignerImpl(first, last, std::move(out),
        //                       ModeAccumulator(SigningMode(Scheme(
        //                           pubkey::detail::key_value<typename Mode::scheme_type>(key_first, key_last)))));
        // }
        //
        // /*!
        //  * @brief
        //  *
        //  * @ingroup pubkey_algorithms
        //  *
        //  * @tparam Scheme
        //  * @tparam InputIterator
        //  * @tparam KeySinglePassRange
        //  * @tparam OutputIterator
        //  *
        //  * @param first
        //  * @param last
        //  * @param key
        //  * @param out
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename InputIterator, typename KeySinglePassRange, typename OutputIterator>
        // OutputIterator sign(InputIterator first, InputIterator last, const KeySinglePassRange &key,
        //                     OutputIterator out) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //     typedef typename pubkey::accumulator_set<SigningMode> ModeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;
        //
        //     return SignerImpl(
        //         first, last, std::move(out),
        //         ModeAccumulator(SigningMode(Scheme(pubkey::detail::key_value<typename
        //         Scheme::scheme_type>(key)))));
        // }
        //
        // /*!
        //  * @brief
        //  *
        //  * @ingroup pubkey_algorithms
        //  *
        //  * @tparam Scheme
        //  * @tparam InputIterator
        //  * @tparam KeyIterator
        //  * @tparam ModeAccumulator
        //  *
        //  * @param first
        //  * @param last
        //  * @param key_first
        //  * @param key_last
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename InputIterator, typename KeyInputIterator,
        //     typename ModeAccumulator = typename pubkey::accumulator_set<typename Mode::template bind<
        //         pubkey::signing_mode_policy<Mode>>::type>>
        // pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<ModeAccumulator>>
        // sign(InputIterator first, InputIterator last, KeyInputIterator key_first, KeyInputIterator key_last) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(first, last,
        //                       ModeAccumulator(SigningMode(Scheme(
        //                           pubkey::detail::key_value<typename Mode::scheme_type>(key_first, key_last)))));
        // }
        //
        // /*!
        //  * @brief
        //  *
        //  * @tparam Scheme
        //  * @tparam InputIterator
        //  * @tparam KeySinglePassRange
        //  * @tparam ModeAccumulator
        //  *
        //  * @param first
        //  * @param last
        //  * @param key
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename InputIterator, typename KeySinglePassRange,
        //     typename ModeAccumulator = typename pubkey::accumulator_set<typename Mode::template bind<
        //         pubkey::signing_mode_policy<Mode>>::type>>
        // pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<ModeAccumulator>>
        // sign(InputIterator first, InputIterator last, const KeySinglePassRange &key) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(first, last,
        //                       ModeAccumulator(SigningMode(
        //                           Scheme(pubkey::detail::key_value<typename Mode::scheme_type>(key)))));
        // }
        //
        //
        // /*!
        //  * @brief
        //  *
        //  * @ingroup pubkey_algorithms
        //  *
        //  * @tparam Scheme
        //  * @tparam SinglePassRange
        //  * @tparam KeyRange
        //  * @tparam OutputIterator
        //  *
        //  * @param rng
        //  * @param key
        //  * @param out
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename SinglePassRange, typename KeySinglePassRange, typename OutputIterator>
        // OutputIterator sign(const SinglePassRange &rng, const KeySinglePassRange &key, OutputIterator out) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //     typedef typename pubkey::accumulator_set<SigningMode> ModeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;
        //
        //     return SignerImpl(rng, std::move(out),
        //                       ModeAccumulator(SigningMode(
        //                           Scheme(pubkey::detail::key_value<typename Mode::scheme_type>(key)))));
        // }
        //
        // /*!
        //  * @brief
        //  *
        //  * @tparam Scheme
        //  * @tparam SinglePassRange
        //  * @tparam KeySinglePassRange
        //  * @tparam OutputRange
        //  *
        //  * @param rng
        //  * @param key
        //  * @param out
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename SinglePassRange, typename KeySinglePassRange, typename OutputRange>
        // OutputRange &sign(const SinglePassRange &rng, const KeySinglePassRange &key, OutputRange &out) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //     typedef typename pubkey::accumulator_set<SigningMode> ModeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(rng, std::move(out),
        //                       ModeAccumulator(SigningMode(
        //                           Scheme(pubkey::detail::key_value<typename Mode::scheme_type>(key)))));
        // }
        //
        // /*!
        //  * @brief
        //  *
        //  * @ingroup pubkey_algorithms
        //  *
        //  * @tparam Scheme
        //  * @tparam SinglePassRange
        //  * @tparam KeyRange
        //  * @tparam ModeAccumulator
        //  *
        //  * @param r
        //  * @param key
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename SinglePassRange, typename KeySinglePassRange,
        //     typename ModeAccumulator = typename pubkey::accumulator_set<typename Mode::template bind<
        //         pubkey::signing_mode_policy<Mode>>::type>>
        // pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<ModeAccumulator>>
        // sign(const SinglePassRange &r, const KeySinglePassRange &key) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(r, ModeAccumulator(SigningMode(
        //         Scheme(pubkey::detail::key_value<typename Mode::scheme_type>(key)))));
        // }
        //
        // /*!
        //  * @brief
        //  *
        //  * * @ingroup pubkey_algorithms
        //  *
        //  * @tparam Scheme
        //  * @tparam SinglePassRange
        //  * @tparam OutputRange
        //  *
        //  * @param rng
        //  * @param key
        //  * @param out
        //  *
        //  * @return
        //  */
        // template<typename Mode, typename SinglePassRange, typename OutputRange>
        // OutputRange &sign(const SinglePassRange &rng, const pubkey::private_key<typename Mode::scheme_type> &key,
        //                   OutputRange &out) {
        //
        //     typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type
        //         SigningMode;
        //     typedef typename pubkey::accumulator_set<SigningMode> ModeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(rng, std::move(out),
        //                       ModeAccumulator(SigningMode(
        //                           Scheme(pubkey::detail::key_value<typename Mode::scheme_type>(key)))));
        // }

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
        OutputIterator sign(InputIterator first, InputIterator last,
                            const pubkey::private_key<typename Mode::scheme_type> &key, OutputIterator out) {

            typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type SigningMode;
            typedef typename pubkey::signing_accumulator_set<SigningMode> ModeAccumulator;

            typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(first, last, std::move(out), ModeAccumulator(key));
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
        OutputIterator sign(const SinglePassRange &rng, const pubkey::private_key<typename Mode::scheme_type> &key,
                            OutputIterator out) {

            typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type SigningMode;
            typedef typename pubkey::signing_accumulator_set<SigningMode> ModeAccumulator;

            typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(rng, std::move(out), ModeAccumulator(key));
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
                 typename OutputAccumulator = typename pubkey::signing_accumulator_set<
                     typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, std::forward<OutputAccumulator>(acc));
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
                 typename OutputAccumulator = typename pubkey::signing_accumulator_set<
                     typename Mode::template bind<typename Mode::signing_mode_policy>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, std::forward<OutputAccumulator>(acc));
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
                 typename ModeAccumulator = typename pubkey::signing_accumulator_set<
                     typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<ModeAccumulator>>
            sign(const SinglePassRange &r, const pubkey::private_key<typename Mode::scheme_type> &key) {

            typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type SigningMode;

            typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, ModeAccumulator(key));
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
                 typename ModeAccumulator = typename pubkey::signing_accumulator_set<
                     typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<ModeAccumulator>>
            sign(InputIterator first, InputIterator last, const pubkey::private_key<typename Mode::scheme_type> &key) {

            typedef typename Mode::template bind<pubkey::signing_mode_policy<Mode>>::type SigningMode;

            typedef pubkey::detail::value_scheme_impl<ModeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, ModeAccumulator(key));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
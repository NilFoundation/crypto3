//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_VERIFY_SHARE_HPP
#define CRYPTO3_PUBKEY_VERIFY_SHARE_HPP

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/secret_sharing_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using share_verification_policy = typename pubkey::modes::isomorphic<Scheme>::share_verification_policy;
        }    // namespace pubkey

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam Number1
         * @tparam Number2
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param n
         * @param t
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename Share, typename OutputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::share_verification_policy<Scheme>>::type>
        OutputIterator verify_share(InputIterator first, InputIterator last, const Share &s, OutputIterator out) {

            typedef typename pubkey::share_verification_accumulator_set<ProcessingMode> SchemeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(first, last, std::move(out), SchemeAccumulator(s));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam Share
         * @tparam OutputIterator
         *
         * @param rng
         * @param s
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename Share, typename OutputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::share_verification_policy<Scheme>>::type>
        OutputIterator verify_share(const SinglePassRange &rng, const Share &s, OutputIterator out) {

            typedef typename pubkey::share_verification_accumulator_set<ProcessingMode> SchemeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(rng, std::move(out), SchemeAccumulator(s));
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
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::share_verification_policy<Scheme>>::type,
                 typename OutputAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            verify_share(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

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
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::share_verification_policy<Scheme>>::type,
                 typename OutputAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            verify_share(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam SchemeAccumulator
         *
         * @param first
         * @param last
         * @param key
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename Share,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::share_verification_policy<Scheme>>::type,
                 typename SchemeAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<SchemeAccumulator>>
            verify_share(InputIterator first, InputIterator last, const Share &s) {

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, SchemeAccumulator(s));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam SchemeAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename Share,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::share_verification_policy<Scheme>>::type,
                 typename SchemeAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<SchemeAccumulator>>
            verify_share(const SinglePassRange &r, const Share &s) {

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, SchemeAccumulator(s));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
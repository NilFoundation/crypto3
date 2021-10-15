//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_DEAL_SHARE_HPP
#define CRYPTO3_PUBKEY_DEAL_SHARE_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/secret_sharing_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using share_dealing_policy = typename pubkey::modes::isomorphic<Scheme>::share_dealing_policy;

            template<typename Scheme>
            using share_dealing_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<share_dealing_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Deal share of specified participant using passed shares, dealt by other participant for the current
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme distribution key generation scheme
         * @tparam InputIterator iterator representing input shares
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         *
         * @param i participant index
         * @param first the beginning of the shares range
         * @param last the end of the shares range
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::share_dealing_processing_mode_default<Scheme>>
        OutputIterator deal_share(std::size_t i, InputIterator first, InputIterator last, OutputIterator out) {

            typedef typename pubkey::share_dealing_accumulator_set<ProcessingMode> DealingAccumulator;

            typedef pubkey::detail::value_pubkey_impl<DealingAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), DealingAccumulator(i));
        }

        /*!
         * @brief Deal share of specified participant using passed shares, dealt by other participant for the current
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme distribution key generation scheme
         * @tparam SinglePassRange range representing input shares
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         *
         * @param i participant index
         * @param range shares range
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::share_dealing_processing_mode_default<Scheme>>
        OutputIterator deal_share(std::size_t i, const SinglePassRange &range, OutputIterator out) {

            typedef typename pubkey::share_dealing_accumulator_set<ProcessingMode> DealingAccumulator;

            typedef pubkey::detail::value_pubkey_impl<DealingAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out), DealingAccumulator(i));
        }

        /*!
         * @brief Updating of share dealing accumulator set using shares, dealt by other participant for the current
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme distribution key generation scheme
         * @tparam InputIterator iterator representing input shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with dealing accumulator (internal parameter)
         *
         * @param first the beginning of the shares range
         * @param last the end of the shares range
         * @param acc accumulator set containing share dealing accumulator possibly pre-initialized with the beginning
         * of shares, dealt by other participant for the current
         *
         * @return OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::share_dealing_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::share_dealing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            deal_share(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating of share dealing accumulator set using shares, dealt by other participant for the current
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme distribution key generation scheme
         * @tparam SinglePassRange range representing input shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with dealing accumulator (internal parameter)
         *
         * @param range shares range
         * @param acc accumulator set containing share dealing accumulator possibly pre-initialized with the beginning
         * of shares, dealt by other participant for the current
         *
         * @return OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::share_dealing_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::share_dealing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            deal_share(const SinglePassRange &range, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Deal share of specified participant using passed shares, dealt by other participant for the current
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme distribution key generation scheme
         * @tparam InputIterator iterator representing input shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p DealingAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param i participant index
         * @param first the beginning of the shares range
         * @param last the end of the shares range
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::share_dealing_processing_mode_default<Scheme>,
                 typename DealingAccumulator = typename pubkey::share_dealing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<DealingAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl deal_share(std::size_t i, InputIterator first, InputIterator last) {

            return SchemeImpl(first, last, DealingAccumulator(i));
        }

        /*!
         * @brief Deal share of specified participant using passed shares, dealt by other participant for the current
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme distribution key generation scheme
         * @tparam SinglePassRange range representing input shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p DealingAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param i participant index
         * @param range shares range
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::share_dealing_processing_mode_default<Scheme>,
                 typename DealingAccumulator = typename pubkey::share_dealing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<DealingAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl deal_share(std::size_t i, const SinglePassRange &range) {

            return SchemeImpl(range, DealingAccumulator(i));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard

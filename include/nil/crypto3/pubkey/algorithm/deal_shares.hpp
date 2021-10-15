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

#ifndef CRYPTO3_PUBKEY_DEAL_SHARES_HPP
#define CRYPTO3_PUBKEY_DEAL_SHARES_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/secret_sharing_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using shares_dealing_policy = typename modes::isomorphic<Scheme>::shares_dealing_policy;

            template<typename Scheme>
            using shares_dealing_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<shares_dealing_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Deal shares using passed polynomial coefficients, threshold number of participants required to
         * reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input polynomial coefficients
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         *
         * @param first the beginning of the polynomial coefficients range
         * @param last the end of the polynomial coefficients range
         * @param n number of participants
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>>
        OutputIterator deal_shares(InputIterator first, InputIterator last, std::size_t n, OutputIterator out) {

            typedef typename pubkey::shares_dealing_accumulator_set<ProcessingMode> DealingAccumulator;

            typedef pubkey::detail::value_pubkey_impl<DealingAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(
                first, last, std::move(out),
                DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = std::distance(first, last)));
        }

        /*!
         * @brief Deal shares using passed polynomial coefficients, threshold number of participants required to
         * reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input polynomial coefficients
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         *
         * @param range the polynomial coefficients range
         * @param n number of participants
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>>
        OutputIterator deal_shares(const SinglePassRange &range, std::size_t n, OutputIterator out) {

            typedef typename pubkey::shares_dealing_accumulator_set<ProcessingMode> DealingAccumulator;

            typedef pubkey::detail::value_pubkey_impl<DealingAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out),
                              DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = range.size()));
        }

        /*!
         * @brief Deal weighted shares using passed polynomial coefficients, threshold number of participants required
         * to reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input polynomial coefficients
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         *
         * @param first the beginning of the polynomial coefficients range
         * @param last the end of the polynomial coefficients range
         * @param n number of participants
         * @param weights participants weights
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>>
        OutputIterator deal_shares(InputIterator first, InputIterator last, std::size_t n,
                                   const typename Scheme::weights_type &weights, OutputIterator out) {

            typedef typename pubkey::shares_dealing_accumulator_set<ProcessingMode> DealingAccumulator;

            typedef pubkey::detail::value_pubkey_impl<DealingAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(
                first, last, std::move(out),
                DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = std::distance(first, last),
                                   nil::crypto3::accumulators::weights = weights));
        }

        /*!
         * @brief Deal weighted shares using passed polynomial coefficients, threshold number of participants required
         * to reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input polynomial coefficients
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         *
         * @param range the polynomial coefficients range
         * @param n number of participants
         * @param weights participants weights
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>>
        OutputIterator deal_shares(const SinglePassRange &range, std::size_t n,
                                   const typename Scheme::weights_type &weights, OutputIterator out) {

            typedef typename pubkey::shares_dealing_accumulator_set<ProcessingMode> DealingAccumulator;

            typedef pubkey::detail::value_pubkey_impl<DealingAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out),
                              DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = range.size(),
                                                 nil::crypto3::accumulators::weights = weights));
        }

        /*!
         * @brief Updating shares dealing accumulator with polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with dealing accumulator (internal parameter)
         *
         * @param first the beginning of the polynomial coefficients range
         * @param last the end of the polynomial coefficients range
         * @param acc accumulator set containing shares dealing accumulator possibly pre-initialized with the beginning
         * of polynomial coefficients and participants number
         *
         * @return OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::shares_dealing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            deal_shares(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating shares dealing accumulator with polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with dealing accumulator (internal parameter)
         *
         * @param range the polynomial coefficients range
         * @param acc accumulator set containing shares dealing accumulator possibly pre-initialized with the beginning
         * of polynomial coefficients and participants number
         *
         * @return OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::shares_dealing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            deal_shares(const SinglePassRange &range, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Deal shares using passed polynomial coefficients, threshold number of participants required to
         * reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam DealingAccumulator accumulator set initialized with shares dealing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p DealingAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the polynomial coefficients range
         * @param last the end of the polynomial coefficients range
         * @param n number of participants
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>,
                 typename DealingAccumulator = typename pubkey::shares_dealing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<DealingAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl deal_shares(InputIterator first, InputIterator last, std::size_t n) {

            return SchemeImpl(
                first, last,
                DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = std::distance(first, last)));
        }

        /*!
         * @brief Deal shares using passed polynomial coefficients, threshold number of participants required to
         * reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam DealingAccumulator accumulator set initialized with shares dealing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p DealingAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range the polynomial coefficients range
         * @param n number of participants
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>,
                 typename DealingAccumulator = typename pubkey::shares_dealing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<DealingAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl deal_shares(const SinglePassRange &range, std::size_t n) {

            return SchemeImpl(range, DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = range.size()));
        }

        /*!
         * @brief Deal weighted shares using passed polynomial coefficients, threshold number of participants required
         * to reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam DealingAccumulator accumulator set initialized with shares dealing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p DealingAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the polynomial coefficients range
         * @param last the end of the polynomial coefficients range
         * @param n number of participants
         * @param weights participants weights
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>,
                 typename DealingAccumulator = typename pubkey::shares_dealing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<DealingAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl deal_shares(InputIterator first, InputIterator last, std::size_t n,
                               const typename Scheme::weights_type &weights) {

            return SchemeImpl(
                first, last,
                DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = std::distance(first, last),
                                   nil::crypto3::accumulators::weights = weights));
        }

        /*!
         * @brief Deal weighted shares using passed polynomial coefficients, threshold number of participants required
         * to reconstruct secret equals to number of the coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a dealing operation as in specification
         * @tparam DealingAccumulator accumulator set initialized with shares dealing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p DealingAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range the polynomial coefficients range
         * @param n number of participants
         * @param weights participants weights
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::shares_dealing_processing_mode_default<Scheme>,
                 typename DealingAccumulator = typename pubkey::shares_dealing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<DealingAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl deal_shares(const SinglePassRange &range, std::size_t n,
                               const typename Scheme::weights_type &weights) {

            return SchemeImpl(range, DealingAccumulator(n, nil::crypto3::accumulators::threshold_value = range.size(),
                                                        nil::crypto3::accumulators::weights = weights));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
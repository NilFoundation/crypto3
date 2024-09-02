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

#ifndef CRYPTO3_PUBKEY_AGGREGATE_HPP
#define CRYPTO3_PUBKEY_AGGREGATE_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/operations/aggregate_op.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using aggregation_policy = typename pubkey::modes::isomorphic<Scheme>::aggregation_policy;

            template<typename Scheme>
            using aggregation_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<aggregation_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Aggregation of the input signatures into one resulted signature and writing it in \p out
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input signatures
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregation operation as in specification
         *
         * @param first the beginning of the signatures range to aggregate
         * @param last the end of the signatures range to aggregate
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::aggregation_processing_mode_default<Scheme>>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            aggregate(InputIterator first, InputIterator last, OutputIterator out) {

            typedef typename pubkey::aggregation_accumulator_set<ProcessingMode> AggregationAccumulator;

            typedef pubkey::detail::value_pubkey_impl<AggregationAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), AggregationAccumulator());
        }

        /*!
         * @brief Aggregation of the input signatures into one resulted signature and writing it in \p out
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input signatures
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregation operation as in specification
         *
         * @param range the signatures range to aggregate
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::aggregation_processing_mode_default<Scheme>>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            aggregate(const SinglePassRange &range, OutputIterator out) {

            typedef typename pubkey::aggregation_accumulator_set<ProcessingMode> AggregationAccumulator;

            typedef pubkey::detail::value_pubkey_impl<AggregationAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out), AggregationAccumulator());
        }

        /*!
         * @brief Updating of accumulator set \p acc containing aggregation accumulator with input signatures
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input signatures
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregation operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregation accumulator (internal parameter)
         *
         * @param first the beginning of the signatures range to aggregate
         * @param last the end of the signatures range to aggregate
         * @param acc accumulator set containing aggregation accumulator possibly pre-initialized with a part of
         * signatures to aggregate
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::aggregation_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::aggregation_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing aggregation accumulator with input signatures
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input signatures
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregation operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregation accumulator (internal parameter)
         *
         * @param range the signatures range to aggregate
         * @param acc accumulator set containing aggregation accumulator possibly pre-initialized with a part of
         * signatures to aggregate
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::aggregation_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::aggregation_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate(const SinglePassRange &range, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Aggregation of the input signatures into one resulted signature
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input signatures
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregation operation as in specification
         * @tparam AggregationAccumulator accumulator set initialized with aggregation accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p AggregationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the signatures range to aggregate
         * @param last the end of the signatures range to aggregate
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::aggregation_processing_mode_default<Scheme>,
                 typename AggregationAccumulator = typename pubkey::aggregation_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<AggregationAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate(InputIterator first, InputIterator last) {
            return SchemeImpl(first, last, AggregationAccumulator());
        }

        /*!
         * @brief Aggregation of the input signatures into one resulted signature
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input signatures
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregation operation as in specification
         * @tparam AggregationAccumulator accumulator set initialized with aggregation accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p AggregationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range the signatures range to aggregate
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::aggregation_processing_mode_default<Scheme>,
                 typename AggregationAccumulator = typename pubkey::aggregation_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<AggregationAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate(const SinglePassRange &range) {
            return SchemeImpl(range, AggregationAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_AGGREGATE_HPP
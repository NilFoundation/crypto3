//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_AGREE_HPP
#define CRYPTO3_PUBKEY_AGREE_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/scheme_value.hpp>
#include <nil/crypto3/pubkey/scheme_state.hpp>

#include <nil/crypto3/pubkey/agreement_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using agreement_policy = typename pubkey::modes::isomorphic<Scheme, nop_padding>::agreement_policy;
        }
        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename KeyInputIterator, typename OutputIterator>
        OutputIterator agree(InputIterator first, InputIterator last, KeyInputIterator key_first,
                               KeyInputIterator key_last, OutputIterator out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(first, last, std::move(out),
                SchemeAccumulator(AgreementMode(
                    Scheme(pubkey::detail::key_value<Scheme>(key_first, key_last)))));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam KeySinglePassRange
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param key
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename KeySinglePassRange, typename OutputIterator>
        OutputIterator agree(InputIterator first, InputIterator last, const KeySinglePassRange &key,
                               OutputIterator out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(
                first, last, std::move(out),
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
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
        template<typename Scheme, typename InputIterator, typename OutputIterator>
        OutputIterator agree(InputIterator first, InputIterator last, const agreement_key<Scheme> &key,
                               OutputIterator out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(
                first, last, std::move(out),
                SchemeAccumulator(AgreementMode(Scheme(key))));
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
                 typename OutputAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::agreement_policy<Scheme>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
        agree(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last, std::forward<OutputAccumulator>(acc));
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
                 typename OutputAccumulator = typename pubkey::accumulator_set<
                     typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                         typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::agreement_policy>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
        agree(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(r, acc);
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam KeyIterator
         * @tparam SchemeAccumulator
         *
         * @param first
         * @param last
         * @param key_first
         * @param key_last
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename KeyInputIterator,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::agreement_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        agree(InputIterator first, InputIterator last, KeyInputIterator key_first, KeyInputIterator key_last) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(first, last,
                SchemeAccumulator(AgreementMode(
                    Scheme(pubkey::detail::key_value<Scheme>(key_first, key_last)))));
        }

        /*!
         * @brief
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
        template<typename Scheme, typename InputIterator, typename KeySinglePassRange,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::agreement_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        agree(InputIterator first, InputIterator last, const KeySinglePassRange &key) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                first, last,
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
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
        template<typename Scheme, typename InputIterator,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::agreement_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        agree(InputIterator first, InputIterator last, const agreement_key<Scheme> &key) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::agreement_policy<Scheme>>::type AgreementMode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                first, last,
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename KeySinglePassRange, typename OutputIterator>
        OutputIterator agree(const SinglePassRange &rng, const KeySinglePassRange &key, OutputIterator out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(
                rng, std::move(out),
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
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
        template<typename Scheme, typename SinglePassRange, typename OutputIterator>
        OutputIterator agree(const SinglePassRange &rng, const agreement_key<Scheme> &key, OutputIterator
                                                                                                           out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamEncrypterImpl, OutputIterator> EncrypterImpl;

            return EncrypterImpl(
                rng, std::move(out),
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
        }

        /*!
         * @brief
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam KeySinglePassRange
         * @tparam OutputRange
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename KeySinglePassRange, typename OutputRange>
        OutputRange &agree(const SinglePassRange &rng, const KeySinglePassRange &key, OutputRange &out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                rng, std::move(out),
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
        }

        /*!
         * @brief
         *
         * * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam OutputRange
         *
         * @param rng
         * @param key
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename OutputRange>
        OutputRange &agree(const SinglePassRange &rng, const agreement_key<Scheme> &key, OutputRange &out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::agreement_policy<Scheme>>::type AgreementMode;
            typedef typename pubkey::accumulator_set<AgreementMode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                rng, std::move(out),
                SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam KeyRange
         * @tparam SchemeAccumulator
         *
         * @param r
         * @param key
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename KeySinglePassRange,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::agreement_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        agree(const SinglePassRange &r, const KeySinglePassRange &key) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
            pubkey::agreement_policy<Scheme>>::type AgreementMode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                r, SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
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
        template<typename Scheme, typename SinglePassRange,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::agreement_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        agree(const SinglePassRange &r, const agreement_key<Scheme> &key) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::agreement_policy<Scheme>>::type AgreementMode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamEncrypterImpl;
            typedef pubkey::detail::range_scheme_impl<StreamEncrypterImpl> EncrypterImpl;

            return EncrypterImpl(
                r, SchemeAccumulator(AgreementMode(Scheme(pubkey::detail::key_value<Scheme>(key)))));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
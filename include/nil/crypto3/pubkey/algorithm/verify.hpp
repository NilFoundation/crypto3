//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_VERIFY_HPP
#define CRYPTO3_PUBKEY_VERIFY_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/scheme_value.hpp>
#include <nil/crypto3/pubkey/scheme_state.hpp>

#include <nil/crypto3/pubkey/public_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using verification_policy = typename pubkey::modes::isomorphic<Scheme, nop_padding>::verification_policy;
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
        template<typename Scheme, typename InputIterator, typename KeyIterator, typename OutputIterator>
        OutputIterator verify(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last,
                            OutputIterator out) {

            typedef typename Scheme::stream_verifyer_type VerificatorMode;
            typedef typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type> VerificatorAccumulator;

            typedef pubkey::detail::value_scheme_impl<VerificatorAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamVerificatorImpl, OutputIterator> VerificatorImpl;

            return VerificatorImpl(first, last, std::move(out), VerificatorState(Scheme(key_first, key_last)));
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
        OutputIterator verify(InputIterator first, InputIterator last, const public_key<Scheme> &key,
                            OutputIterator out) {

            typedef typename Scheme::stream_verifyer_type VerificatorMode;
            typedef typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type> VerificatorAccumulator;

            typedef pubkey::detail::value_scheme_impl<VerificatorAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamVerificatorImpl, OutputIterator> VerificatorImpl;

            return VerificatorImpl(first, last, std::move(out), VerificatorState(Scheme(key)));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam SchemeAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename Scheme, typename InputIterator,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type>>
        SchemeAccumulator &verify(InputIterator first, InputIterator last, SchemeAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<SchemeAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::range_scheme_impl<StreamVerificatorImpl> VerificatorImpl;

            return VerificatorImpl(first, last, acc);
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
                 typename OutputAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type>>
        OutputAccumulator &verify(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::range_scheme_impl<StreamVerificatorImpl> VerificatorImpl;

            return VerificatorImpl(r, acc);
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
        template<typename Scheme, typename InputIterator, typename KeyIterator,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        verify(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last) {

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::range_scheme_impl<StreamVerificatorImpl> VerificatorImpl;

            return VerificatorImpl(first, last, SchemeAccumulator(Scheme(key_first, key_last)));
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
        template<typename Scheme, typename SinglePassRange, typename KeyRange, typename OutputIterator>
        OutputIterator verify(const SinglePassRange &rng, const KeyRange &key, OutputIterator out) {

            typedef typename Scheme::stream_verifyer_type SignionMode;
            typedef typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamVerificatorImpl, OutputIterator> VerificatorImpl;

            return VerificatorImpl(rng, std::move(out), SchemeState(Scheme(key)));
        }

        /*!
         * @brief
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
        OutputIterator verify(const SinglePassRange &rng, const public_key<Scheme> &key, OutputIterator out) {

            typedef typename Scheme::stream_verifyer_type SignionMode;
            typedef typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type>
                SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamVerificatorImpl, OutputIterator> VerificatorImpl;

            return VerificatorImpl(rng, std::move(out), SchemeState(Scheme(key)));
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
        template<typename Scheme, typename SinglePassRange, typename KeyRange,
                 typename SchemeAccumulator = typename pubkey::accumulator_set<typename pubkey::modes::isomorphic<
                     Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        verify(const SinglePassRange &r, const KeyRange &key) {

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::range_scheme_impl<StreamVerificatorImpl> VerificatorImpl;

            return VerificatorImpl(r, SchemeState(Scheme(key)));
        }

        /*!
         * @brief
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
                     Scheme, pubkey::nop_padding>::template bind<pubkey::verification_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        verify(const SinglePassRange &r, const public_key<Scheme> &key) {

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamVerificatorImpl;
            typedef pubkey::detail::range_scheme_impl<StreamVerificatorImpl> VerificatorImpl;

            return VerificatorImpl(r, SchemeState(Scheme(key)));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
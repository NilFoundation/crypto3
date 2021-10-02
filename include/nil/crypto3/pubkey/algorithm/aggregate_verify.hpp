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

#ifndef CRYPTO3_PUBKEY_AGGREGATE_VERIFY_HPP
#define CRYPTO3_PUBKEY_AGGREGATE_VERIFY_HPP

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using aggregate_verification_policy =
                typename pubkey::modes::isomorphic<Scheme>::aggregate_verification_policy;
        }    // namespace pubkey

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         *
         * @param first
         * @param last
         *
         * @return
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::aggregate_verification_policy<Scheme>>::type,
                 typename SchemeAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SchemeAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate_verify(InputIterator first, InputIterator last,
                                    const typename pubkey::public_key<Scheme>::signature_type &signature,
                                    const pubkey::public_key<Scheme> &key) {
            return SchemeImpl(first, last, SchemeAccumulator(signature), key);
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         *
         * @param rng
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::aggregate_verification_policy<Scheme>>::type,
                 typename SchemeAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SchemeAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate_verify(const SinglePassRange &rng,
                                    const typename pubkey::public_key<Scheme>::signature_type &signature,
                                    const pubkey::public_key<Scheme> &key) {
            return SchemeImpl(rng, SchemeAccumulator(signature), key);
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
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
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::aggregate_verification_policy<Scheme>>::type,
                 typename OutputAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate_verify(InputIterator first, InputIterator last, const pubkey::public_key<Scheme> &key,
                             OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc), key);
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam VerificationPolicy
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::aggregate_verification_policy<Scheme>>::type,
                 typename OutputAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate_verify(const SinglePassRange &r, const pubkey::public_key<Scheme> &key, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(r, std::forward<OutputAccumulator>(acc), key);
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
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator>
        OutputIterator aggregate_verify(InputIterator first, InputIterator last,
                                        const typename pubkey::public_key<Scheme>::signature_type &signature,
                                        const pubkey::public_key<Scheme> &key, OutputIterator out) {
            typedef typename pubkey::modes::isomorphic<Scheme>::template bind<
                pubkey::aggregate_verification_policy<Scheme>>::type ProcessingMode;
            typedef pubkey::aggregate_verification_accumulator_set<ProcessingMode> SchemeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), SchemeAccumulator(signature), key);
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
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator>
        OutputIterator aggregate_verify(const SinglePassRange &rng,
                                        const typename pubkey::public_key<Scheme>::signature_type &signature,
                                        const pubkey::public_key<Scheme> &key, OutputIterator out) {
            typedef typename pubkey::modes::isomorphic<Scheme>::template bind<
                pubkey::aggregate_verification_policy<Scheme>>::type ProcessingMode;
            typedef pubkey::aggregate_verification_accumulator_set<ProcessingMode> SchemeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(rng, std::move(out), SchemeAccumulator(signature), key);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
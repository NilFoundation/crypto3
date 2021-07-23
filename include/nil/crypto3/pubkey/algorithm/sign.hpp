//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_SIGN_HPP
#define CRYPTO3_PUBKEY_SIGN_HPP

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief
             *
             * @ingroup pubkey_algorithms
             *
             * A digital signature is a mathematical scheme for verifying the authenticity of
             * digital messages or documents. A valid digital signature, where the prerequisites
             * are satisfied, gives a recipient very strong reason to believe that the message
             * was created by a known sender (authentication), and that the message was not altered
             * in transit (integrity).
             *
             * The function sign takes as input parameters - a message to be signed, a private key for
             * signing and an iterator for output the message. Once executed, the function returns a
             * signed message.
             */
            template<typename Scheme>
            using signing_policy = typename pubkey::modes::isomorphic<Scheme>::signing_policy;
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
         * @param key
         *
         * @return
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode =
                     typename pubkey::modes::isomorphic<Scheme>::template bind<pubkey::signing_policy<Scheme>>::type,
                 typename SigningAccumulator = pubkey::signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(first, last, SigningAccumulator(key));
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
         * @param key
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode =
                     typename pubkey::modes::isomorphic<Scheme>::template bind<pubkey::signing_policy<Scheme>>::type,
                 typename SigningAccumulator = pubkey::signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(const SinglePassRange &rng, const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(rng, SigningAccumulator(key));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam InputIterator
         * @tparam EncodingPolicy
         * @tparam OutputAccumulator
         *
         * @param first
         * @param last
         * @param acc
         *
         * @return
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode =
                     typename pubkey::modes::isomorphic<Scheme>::template bind<pubkey::signing_policy<Scheme>>::type,
                 typename OutputAccumulator = pubkey::signing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(InputIterator first, InputIterator last, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme
         * @tparam SinglePassRange
         * @tparam EncodingPolicy
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode =
                     typename pubkey::modes::isomorphic<Scheme>::template bind<pubkey::signing_policy<Scheme>>::type,
                 typename OutputAccumulator = pubkey::signing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(const SinglePassRange &r, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(r, std::forward<OutputAccumulator>(acc));
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
        OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key,
                            OutputIterator out) {
            typedef typename pubkey::modes::isomorphic<Scheme>::template bind<pubkey::signing_policy<Scheme>>::type
                ProcessingMode;
            typedef pubkey::signing_accumulator_set<ProcessingMode> SigningAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SigningAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), SigningAccumulator(key));
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
        OutputIterator sign(const SinglePassRange &rng, const pubkey::private_key<Scheme> &key, OutputIterator out) {
            typedef typename pubkey::modes::isomorphic<Scheme>::template bind<pubkey::signing_policy<Scheme>>::type
                ProcessingMode;
            typedef pubkey::signing_accumulator_set<ProcessingMode> SigningAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SigningAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(rng, std::move(out), SigningAccumulator(key));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard

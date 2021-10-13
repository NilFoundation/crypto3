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

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using aggregate_verification_policy =
                typename pubkey::modes::isomorphic<Scheme>::aggregate_verification_policy;

            template<typename Scheme>
            using aggregate_verification_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<aggregate_verification_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Aggregate verification of the input aggregated signature that aggregates signature created for the
         * input message on the \p key.
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam AggregateVerificationAccumulator accumulator set initialized with aggregate verification accumulator
         * (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p AggregateVerificationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the message range, corresponding to passed \p key
         * @param last the end of the message range, corresponding to passed \p key
         * @param signature aggregated signature to verify
         * @param key one of the public keys, which corresponding private key was used to sign the passed message
         *
         * @return \p SchemeImpl
         */
        template<
            typename Scheme, typename InputIterator,
            typename ProcessingMode = pubkey::aggregate_verification_processing_mode_default<Scheme>,
            typename AggregateVerificationAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>,
            typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<AggregateVerificationAccumulator>,
            typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate_verify(InputIterator first, InputIterator last,
                                    const typename pubkey::public_key<Scheme>::signature_type &signature,
                                    const pubkey::public_key<Scheme> &key) {
            return SchemeImpl(first, last, AggregateVerificationAccumulator(signature), key);
        }

        /*!
         * @brief Aggregate verification of the input aggregated signature that aggregates signature created for the
         * input message on the \p key.
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam AggregateVerificationAccumulator accumulator set initialized with aggregate verification accumulator
         * (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p AggregateVerificationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range the message range, corresponding to passed \p key
         * @param signature aggregated signature to verify
         * @param key one of the public keys, which corresponding private key was used to sign the passed message
         *
         * @return \p SchemeImpl
         */
        template<
            typename Scheme, typename SinglePassRange,
            typename ProcessingMode = pubkey::aggregate_verification_processing_mode_default<Scheme>,
            typename AggregateVerificationAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>,
            typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<AggregateVerificationAccumulator>,
            typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate_verify(const SinglePassRange &range,
                                    const typename pubkey::public_key<Scheme>::signature_type &signature,
                                    const pubkey::public_key<Scheme> &key) {
            return SchemeImpl(range, AggregateVerificationAccumulator(signature), key);
        }

        /*!
         * @brief Updating of accumulator set \p acc containing aggregate verification accumulator with input message
         * and corresponding public key
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregate verification accumulator (internal
         * parameter)
         *
         * @param first the beginning of the message range, corresponding to passed \p key
         * @param last the end of the message range, corresponding to passed \p key
         * @param key one of the public keys, which corresponding private key was used to sign the passed message
         * @param acc accumulator set containing aggregate verification accumulator possibly pre-initialized with a part
         * of signatures to aggregate
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::aggregate_verification_processing_mode_default<Scheme>,
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
         * @brief Updating of accumulator set \p acc containing aggregate verification accumulator with input message
         * and corresponding public key
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input signatures
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregate verification accumulator (internal
         * parameter)
         *
         * @param range the message range, corresponding to passed \p key
         * @param key one of the public keys, which corresponding private key was used to sign the passed message
         * @param acc accumulator set containing aggregate verification accumulator possibly pre-initialized with a part
         * of signatures to aggregate
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::aggregate_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate_verify(const SinglePassRange &range, const pubkey::public_key<Scheme> &key,
                             OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc), key);
        }

        /*!
         * @brief Updating of accumulator set \p acc containing aggregate verification accumulator with verified
         * aggregated signature
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregate verification accumulator (internal
         * parameter)
         *
         * @param aggregated_signature signature to verify
         * @param acc accumulator set containing aggregate verification accumulator possibly pre-initialized with a part
         * of signatures to aggregate
         *
         * @return \p OutputAccumulator
         */
        // TODO: fix
        template<typename Scheme,
                 typename ProcessingMode = pubkey::aggregate_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate_verify(const typename pubkey::public_key<Scheme>::signature_type &aggregated_signature,
                             OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(std::forward<OutputAccumulator>(acc), aggregated_signature);
        }

        /*!
         * @brief Extracting of accumulator set \p acc containing aggregate verification accumulator and writing result
         * in \p out.
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam AggregateVerificationAccumulator accumulator set initialized with aggregate verification accumulator
         * (internal parameter)
         *
         * @param acc accumulator set containing aggregate verification accumulator possibly pre-initialized with a part
         * of signatures to aggregate
         * @param out the beginning of the destination range
         *
         * @return \p SchemeImpl
         */
        // TODO: check
        template<typename Scheme, typename OutputIterator,
                 typename ProcessingMode = pubkey::aggregate_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputIterator>::type
            aggregate_verify(OutputAccumulator &acc, OutputIterator out) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(std::move(out), std::forward<OutputAccumulator>(acc));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
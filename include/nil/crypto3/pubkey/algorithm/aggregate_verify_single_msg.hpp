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

#ifndef CRYPTO3_PUBKEY_AGGREGATE_VERIFY_SINGLE_MSG_HPP
#define CRYPTO3_PUBKEY_AGGREGATE_VERIFY_SINGLE_MSG_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using single_msg_aggregate_verification_policy =
                typename pubkey::modes::isomorphic<Scheme>::single_msg_aggregate_verification_policy;

            template<typename Scheme>
            using single_msg_aggregate_verification_processing_mode_default = typename modes::isomorphic<
                Scheme>::template bind<single_msg_aggregate_verification_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Aggregate verification of the input aggregated signature that is aggregation of signatures created for
         * the single input message on the input list of key.
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator1 iterator representing input message
         * @tparam InputIterator2 iterator representing input public keys which corresponding private keys were used to
         * sign input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation of single message as in specification
         * @tparam AggregateVerificationAccumulator accumulator set initialized with aggregate verification accumulator
         * (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p AggregateVerificationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param msg_first the beginning of the message range
         * @param msg_last the end of the message range
         * @param key_first the beginning of the key range
         * @param key_last the end of the key range
         * @param signature aggregated signature to verify
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename InputIterator1, typename InputIterator2,
                 typename ProcessingMode = pubkey::single_msg_aggregate_verification_processing_mode_default<Scheme>,
                 typename AggregateVerificationAccumulator =
                     pubkey::single_msg_aggregate_verification_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<AggregateVerificationAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate_verify_single_msg(InputIterator1 msg_first, InputIterator1 msg_last,
                                               InputIterator2 key_first, InputIterator2 key_last,
                                               const typename pubkey::public_key<Scheme>::signature_type &signature) {
            return SchemeImpl(msg_first, msg_last, key_first, key_last, AggregateVerificationAccumulator(signature));
        }

        /*!
         * @brief Aggregate verification of the input aggregated signature that is aggregation of signatures created for
         * the single input message on the input list of key.
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange1 range representing input message
         * @tparam SinglePassRange2 range representing input public keys which corresponding private keys were used to
         * sign input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation of single message as in specification
         * @tparam AggregateVerificationAccumulator accumulator set initialized with aggregate verification accumulator
         * (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p AggregateVerificationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param msg_rng the message range
         * @param keys_rng the key range
         * @param signature aggregated signature to verify
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange1, typename SinglePassRange2,
                 typename ProcessingMode = pubkey::single_msg_aggregate_verification_processing_mode_default<Scheme>,
                 typename AggregateVerificationAccumulator =
                     pubkey::single_msg_aggregate_verification_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<AggregateVerificationAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl aggregate_verify_single_msg(const SinglePassRange1 &msg_rng,
                                               const SinglePassRange2 &keys_rng,
                                               const typename pubkey::public_key<Scheme>::signature_type &signature) {
            return SchemeImpl(std::cbegin(msg_rng), std::cend(msg_rng), std::cbegin(keys_rng), std::cend(keys_rng),
                              AggregateVerificationAccumulator(signature));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing aggregate verification accumulator with input message
         * or public keys
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input message or range of public keys
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregate verification accumulator (internal
         * parameter)
         *
         * @param first the beginning of the message or public keys range
         * @param last the end of the message or public keys range
         * @param acc accumulator set containing aggregate verification accumulator possibly pre-initialized
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::single_msg_aggregate_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::single_msg_aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate_verify_single_msg(InputIterator first, InputIterator last, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing aggregate verification accumulator with input message
         * or public keys
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input message or public keys
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with aggregate verification accumulator (internal
         * parameter)
         *
         * @param range the beginning of the message or public keys range
         * @param acc accumulator set containing aggregate verification accumulator possibly pre-initialized
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::single_msg_aggregate_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::single_msg_aggregate_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            aggregate_verify_single_msg(const SinglePassRange &range, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Aggregate verification of the input aggregated signature that is aggregation of signatures created for
         * the single input message on the input list of key and writing result in \p out
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator1 iterator representing input message
         * @tparam InputIterator2 iterator representing input public keys which corresponding private keys were used to
         * sign input message
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation of single message as in specification
         *
         * @param msg_first the beginning of the message range
         * @param msg_last the end of the message range
         * @param key_first the beginning of the key range
         * @param key_last the end of the key range
         * @param signature aggregated signature to verify
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename InputIterator1, typename InputIterator2, typename OutputIterator,
                 typename ProcessingMode = pubkey::single_msg_aggregate_verification_processing_mode_default<Scheme>>
        OutputIterator aggregate_verify_single_msg(InputIterator1 msg_first, InputIterator1 msg_last,
                                                   InputIterator2 key_first, InputIterator2 key_last,
                                                   const typename pubkey::public_key<Scheme>::signature_type &signature,
                                                   OutputIterator out) {
            typedef pubkey::single_msg_aggregate_verification_accumulator_set<ProcessingMode>
                AggregateVerificationAccumulator;

            typedef pubkey::detail::value_pubkey_impl<AggregateVerificationAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(msg_first, msg_last, key_first, key_last, std::move(out),
                              AggregateVerificationAccumulator(signature));
        }

        /*!
         * @brief Aggregate verification of the input aggregated signature that is aggregation of signatures created for
         * the single input message on the input list of key and writing result in \p out
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange1 range representing input message
         * @tparam SinglePassRange2 range representing input public keys which corresponding private keys were used to
         * sign input message
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing an aggregate verification operation of single message as in specification
         *
         * @param msg_rng the message range
         * @param keys_rng the key range
         * @param signature aggregated signature to verify
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename SinglePassRange1, typename SinglePassRange2, typename OutputIterator,
                 typename ProcessingMode = pubkey::single_msg_aggregate_verification_processing_mode_default<Scheme>>
        OutputIterator aggregate_verify_single_msg(const SinglePassRange1 &msg_rng, const SinglePassRange2 &keys_rng,
                                                   const typename pubkey::public_key<Scheme>::signature_type &signature,
                                                   OutputIterator out) {
            typedef pubkey::single_msg_aggregate_verification_accumulator_set<ProcessingMode>
                AggregateVerificationAccumulator;

            typedef pubkey::detail::value_pubkey_impl<AggregateVerificationAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(std::cbegin(msg_rng), std::cend(msg_rng), std::cbegin(keys_rng), std::cend(keys_rng),
                              std::move(out), AggregateVerificationAccumulator(signature));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
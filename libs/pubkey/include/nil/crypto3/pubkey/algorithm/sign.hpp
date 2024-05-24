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

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using signing_policy = typename pubkey::modes::isomorphic<Scheme>::signing_policy;

            template<typename Scheme>
            using pop_proving_policy = typename pubkey::modes::isomorphic<Scheme>::pop_proving_policy;

            template<typename Scheme>
            using signing_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<signing_policy<Scheme>>::type;

            template<typename Scheme>
            using pop_proving_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<pop_proving_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Proving of possession of the supplied key
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         * @tparam SigningAccumulator accumulator set initialized with signing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p SigningAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param key private key to be proved by signing it on itself
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename ProcessingMode = pubkey::pop_proving_processing_mode_default<Scheme>,
                 typename SigningAccumulator = pubkey::signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(SigningAccumulator(key));
        }

        /*!
         * @brief Signing of the input message on the \p key
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         * @tparam SigningAccumulator accumulator set initialized with signing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p SigningAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the message range to sign
         * @param last the end of the message range to sign
         * @param key private key to be used for signing
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::signing_processing_mode_default<Scheme>,
                 typename SigningAccumulator = pubkey::signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(first, last, SigningAccumulator(key));
        }

        /*!
         * @brief Signing of the input message on the \p key
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         * @tparam SigningAccumulator accumulator set initialized with signing accumulator (internal parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p SigningAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range the message range to sign
         * @param key private key to be used for signing
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::signing_processing_mode_default<Scheme>,
                 typename SigningAccumulator = pubkey::signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(const SinglePassRange &range, const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(range, SigningAccumulator(key));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing signing accumulator with input message
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         * @tparam OutputAccumulator accumulator set initialized with signing accumulator (internal parameter)
         *
         * @param first the beginning of the message range to sign
         * @param last the end of the message range to sign
         * @param acc accumulator set containing signing accumulator initialized with private key and possibly
         * pre-initialized with the beginning of message to be signed
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::signing_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::signing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(InputIterator first, InputIterator last, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing signing accumulator with input message
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input message
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         * @tparam OutputAccumulator accumulator set initialized with signing accumulator (internal parameter)
         *
         * @param range the message range to sign
         * @param acc accumulator set containing signing accumulator initialized with private key and possibly
         * pre-initialized with the beginning of message to be signed
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::signing_processing_mode_default<Scheme>,
                 typename OutputAccumulator = pubkey::signing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(const SinglePassRange &range, OutputAccumulator &acc) {
            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Signing of the input message on the \p key and writing result in \p out
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input message
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         *
         * @param first the beginning of the message range to sign
         * @param last the end of the message range to sign
         * @param key private key to be used for signing
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::signing_processing_mode_default<Scheme>>
        OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key,
                            OutputIterator out) {
            typedef pubkey::signing_accumulator_set<ProcessingMode> SigningAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SigningAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), SigningAccumulator(key));
        }

        /*!
         * @brief Signing of the input message on the \p key and writing result in \p out
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input message
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a signing operation as in specification, another example is threshold mode
         *
         * @param range the message range to sign
         * @param key private key to be used for signing
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::signing_processing_mode_default<Scheme>>
        OutputIterator sign(const SinglePassRange &range, const pubkey::private_key<Scheme> &key, OutputIterator out) {
            typedef pubkey::signing_accumulator_set<ProcessingMode> SigningAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SigningAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out), SigningAccumulator(key));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SIGN_HPP

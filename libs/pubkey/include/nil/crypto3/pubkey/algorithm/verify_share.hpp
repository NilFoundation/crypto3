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

#ifndef CRYPTO3_PUBKEY_VERIFY_SHARE_HPP
#define CRYPTO3_PUBKEY_VERIFY_SHARE_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/secret_sharing_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using share_verification_policy = typename pubkey::modes::isomorphic<Scheme>::share_verification_policy;

            template<typename Scheme>
            using share_verification_processing_mode_default =
                typename modes::isomorphic<Scheme>::template bind<share_verification_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Verification of the share on the input public representatives of polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input public representatives of polynomial coefficients
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a verification operation as in specification, another example is threshold mode
         *
         * @param first the beginning of the public representatives of polynomial coefficients range
         * @param last the end of the public representatives of polynomial coefficients range
         * @param s verified share
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::share_verification_processing_mode_default<Scheme>>
        OutputIterator verify_share(InputIterator first, InputIterator last, const pubkey::public_share_sss<Scheme> &s,
                                    OutputIterator out) {

            typedef typename pubkey::share_verification_accumulator_set<ProcessingMode> VerificationAccumulator;

            typedef pubkey::detail::value_pubkey_impl<VerificationAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), VerificationAccumulator(s));
        }

        /*!
         * @brief Verification of the share on the input public representatives of polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input public representatives of polynomial coefficients
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a verification operation as in specification, another example is threshold mode
         *
         * @param range public representatives of polynomial coefficients range
         * @param s verified share
         * @param out the beginning of the destination range
         *
         * @return \p OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::share_verification_processing_mode_default<Scheme>>
        OutputIterator verify_share(const SinglePassRange &range, const pubkey::public_share_sss<Scheme> &s,
                                    OutputIterator out) {

            typedef typename pubkey::share_verification_accumulator_set<ProcessingMode> VerificationAccumulator;

            typedef pubkey::detail::value_pubkey_impl<VerificationAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out), VerificationAccumulator(s));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing verification accumulator with public representatives of
         * polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing public representatives of polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with verification accumulator (internal parameter)
         *
         * @param first the beginning of the public representatives of polynomial coefficients range
         * @param last the end of the public representatives of polynomial coefficients range
         * @param acc accumulator set containing verification accumulator initialized with public key and possibly
         * pre-initialized with the beginning of public representatives of shares range
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::share_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            verify_share(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating of accumulator set \p acc containing verification accumulator with public representatives of
         * polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing public representatives of polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a verification operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with verification accumulator (internal parameter)
         *
         * @param range public representatives of polynomial coefficients range
         * @param acc accumulator set containing verification accumulator initialized with public key and possibly
         * pre-initialized with the beginning of public representatives of shares range
         *
         * @return \p OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::share_verification_processing_mode_default<Scheme>,
                 typename OutputAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            verify_share(const SinglePassRange &range, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Verification of the share on the input public representatives of polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam InputIterator iterator representing input public representatives of polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a verification operation as in specification, another example is threshold mode
         * @tparam VerificationAccumulator accumulator set initialized with verification accumulator (internal
         * parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p VerificationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the public representatives of polynomial coefficients range
         * @param last the end of the public representatives of polynomial coefficients range
         * @param s verified share
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::share_verification_processing_mode_default<Scheme>,
                 typename VerificationAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<VerificationAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl verify_share(InputIterator first, InputIterator last, const pubkey::public_share_sss<Scheme> &s) {

            return SchemeImpl(first, last, VerificationAccumulator(s));
        }

        /*!
         * @brief Verification of the share on the input public representatives of polynomial coefficients
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme public key signature scheme
         * @tparam SinglePassRange range representing input public representatives of polynomial coefficients
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a verification operation as in specification, another example is threshold mode
         * @tparam VerificationAccumulator accumulator set initialized with verification accumulator (internal
         * parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p VerificationAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range public representatives of polynomial coefficients range
         * @param s verified share
         *
         * @return \p SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::share_verification_processing_mode_default<Scheme>,
                 typename VerificationAccumulator = typename pubkey::share_verification_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<VerificationAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl verify_share(const SinglePassRange &range, const pubkey::public_share_sss<Scheme> &s) {

            return SchemeImpl(range, VerificationAccumulator(s));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
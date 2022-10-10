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

#ifndef CRYPTO3_PUBKEY_RECONSTRUCT_PUBLIC_SECRET_HPP
#define CRYPTO3_PUBKEY_RECONSTRUCT_PUBLIC_SECRET_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/secret_sharing_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using public_secret_reconstructing_policy =
                typename pubkey::modes::isomorphic<Scheme>::public_secret_reconstructing_policy;

            template<typename Scheme>
            using public_secret_reconstructing_processing_mode =
                typename modes::isomorphic<Scheme>::template bind<public_secret_reconstructing_policy<Scheme>>::type;
        }    // namespace pubkey

        /*!
         * @brief Reconstruct public representative of secret using passed public representatives of shares
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input public representatives of shares
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a reconstruction operation as in specification
         *
         * @param first the beginning of the public representatives of shares range
         * @param last the end of the public representatives of shares range
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = pubkey::public_secret_reconstructing_processing_mode<Scheme>>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            reconstruct_public_secret(InputIterator first, InputIterator last, OutputIterator out) {

            typedef typename pubkey::reconstructing_accumulator_set<ProcessingMode> ReconstructionAccumulator;

            typedef pubkey::detail::value_pubkey_impl<ReconstructionAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), ReconstructionAccumulator());
        }

        /*!
         * @brief Reconstruct public representative of secret using passed public representatives of shares
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input public representatives of shares
         * @tparam OutputIterator iterator representing output range with value type of \p ProcessingMode::result_type
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a reconstruction operation as in specification
         *
         * @param range public representatives of shares range
         * @param out the beginning of the destination range
         *
         * @return OutputIterator
         */
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = pubkey::public_secret_reconstructing_processing_mode<Scheme>>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            reconstruct_public_secret(const SinglePassRange &range, OutputIterator out) {

            typedef typename pubkey::reconstructing_accumulator_set<ProcessingMode> ReconstructionAccumulator;

            typedef pubkey::detail::value_pubkey_impl<ReconstructionAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out), ReconstructionAccumulator());
        }

        /*!
         * @brief Updating of reconstructing accumulator set using passed public representatives of shares
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input public representatives of shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a reconstructing operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with reconstructing accumulator (internal parameter)
         *
         * @param first the beginning of the public representatives of shares range
         * @param last the end of the public representatives of shares range
         * @param acc accumulator set containing secret reconstructing accumulator possibly pre-initialized with the
         * beginning of public representatives of shares range
         *
         * @return OutputAccumulator
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::public_secret_reconstructing_processing_mode<Scheme>,
                 typename OutputAccumulator = typename pubkey::reconstructing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            reconstruct_public_secret(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Updating of reconstructing accumulator set using passed public representatives of shares
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input public representatives of shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a reconstructing operation as in specification
         * @tparam OutputAccumulator accumulator set initialized with reconstructing accumulator (internal parameter)
         *
         * @param range public representatives of shares range
         * @param acc accumulator set containing secret reconstructing accumulator possibly pre-initialized with the
         * beginning of public representatives of shares range
         *
         * @return OutputAccumulator
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::public_secret_reconstructing_processing_mode<Scheme>,
                 typename OutputAccumulator = typename pubkey::reconstructing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            reconstruct_public_secret(const SinglePassRange &range, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief Reconstruct public representative of secret using passed public representatives of shares
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam InputIterator iterator representing input public representatives of shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a reconstruction operation as in specification
         * @tparam ReconstructionAccumulator accumulator set initialized with reconstruction accumulator (internal
         * parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p ReconstructionAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param first the beginning of the public representatives of shares range
         * @param last the end of the public representatives of shares range
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename InputIterator,
                 typename ProcessingMode = pubkey::public_secret_reconstructing_processing_mode<Scheme>,
                 typename ReconstructionAccumulator = typename pubkey::reconstructing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<ReconstructionAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl reconstruct_public_secret(InputIterator first, InputIterator last) {

            return SchemeImpl(first, last, ReconstructionAccumulator());
        }

        /*!
         * @brief Reconstruct public representative of secret using passed public representatives of shares
         *
         * @ingroup pubkey_algorithms
         *
         * @tparam Scheme secret sharing scheme
         * @tparam SinglePassRange range representing input public representatives of shares
         * @tparam ProcessingMode a policy representing a work mode of the scheme, by default isomorphic, which means
         * executing a reconstruction operation as in specification
         * @tparam ReconstructionAccumulator accumulator set initialized with reconstruction accumulator (internal
         * parameter)
         * @tparam StreamSchemeImpl (internal parameter)
         * @tparam SchemeImpl return type implicitly convertible to \p ReconstructionAccumulator or \p
         * ProcessingMode::result_type (internal parameter)
         *
         * @param range public representatives of shares range
         *
         * @return SchemeImpl
         */
        template<typename Scheme, typename SinglePassRange,
                 typename ProcessingMode = pubkey::public_secret_reconstructing_processing_mode<Scheme>,
                 typename ReconstructionAccumulator = typename pubkey::reconstructing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<ReconstructionAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl reconstruct_public_secret(const SinglePassRange &range) {

            return SchemeImpl(range, ReconstructionAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
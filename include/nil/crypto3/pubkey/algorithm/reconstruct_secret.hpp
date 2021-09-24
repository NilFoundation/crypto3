//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_RECONSTRUCT_SECRET_HPP
#define CRYPTO3_PUBKEY_RECONSTRUCT_SECRET_HPP

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/secret_sharing_state.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using secret_reconstructing_policy =
                typename pubkey::modes::isomorphic<Scheme>::secret_reconstructing_policy;
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
        template<typename Scheme, typename InputIterator, typename OutputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::secret_reconstructing_policy<Scheme>>::type>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            reconstruct(InputIterator first, InputIterator last, OutputIterator out) {

            typedef typename pubkey::secret_reconstructing_accumulator_set<ProcessingMode> SchemeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(first, last, std::move(out), SchemeAccumulator());
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
        template<typename Scheme, typename SinglePassRange, typename OutputIterator,
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::secret_reconstructing_policy<Scheme>>::type>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                OutputIterator>::type
            reconstruct(const SinglePassRange &rng, OutputIterator out) {

            typedef typename pubkey::secret_reconstructing_accumulator_set<ProcessingMode> SchemeAccumulator;

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(rng, std::move(out), SchemeAccumulator());
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
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::secret_reconstructing_policy<Scheme>>::type,
                 typename OutputAccumulator = typename pubkey::secret_reconstructing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            reconstruct(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, std::forward<OutputAccumulator>(acc));
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
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::secret_reconstructing_policy<Scheme>>::type,
                 typename OutputAccumulator = typename pubkey::secret_reconstructing_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            reconstruct(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, std::forward<OutputAccumulator>(acc));
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
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::secret_reconstructing_policy<Scheme>>::type,
                 typename SchemeAccumulator = typename pubkey::secret_reconstructing_accumulator_set<ProcessingMode>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<SchemeAccumulator>>
            reconstruct(InputIterator first, InputIterator last) {

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, SchemeAccumulator());
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
                 typename ProcessingMode = typename pubkey::modes::isomorphic<Scheme>::template bind<
                     pubkey::secret_reconstructing_policy<Scheme>>::type,
                 typename SchemeAccumulator = typename pubkey::secret_reconstructing_accumulator_set<ProcessingMode>>
        pubkey::detail::range_pubkey_impl<pubkey::detail::value_pubkey_impl<SchemeAccumulator>>
            reconstruct(const SinglePassRange &r) {

            typedef pubkey::detail::value_pubkey_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, SchemeAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
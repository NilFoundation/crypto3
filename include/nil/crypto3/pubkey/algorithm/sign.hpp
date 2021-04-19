//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_SIGN_HPP
#define CRYPTO3_PUBKEY_SIGN_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/scheme_value.hpp>
#include <nil/crypto3/pubkey/scheme_state.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

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
         *
         *
         * @brief Algorithms are meant to provide hashing interface similar to STL algorithms' one.
         */
            template<typename Scheme>
            using signing_policy = typename pubkey::modes::isomorphic<Scheme, nop_padding>::signing_policy;
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
        // template<typename Scheme, typename InputIterator, typename KeyInputIterator, typename OutputIterator>
        // OutputIterator sign(InputIterator first, InputIterator last, KeyInputIterator key_first,
        //                     KeyInputIterator key_last, OutputIterator out) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //     typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;
        //
        //     return SignerImpl(first, last, std::move(out),
        //                       SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key_first, key_last)))));
        // }

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
        // template<typename Scheme, typename InputIterator, typename KeySinglePassRange, typename OutputIterator>
        // OutputIterator sign(InputIterator first, InputIterator last, const KeySinglePassRange &key,
        //                     OutputIterator out) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //     typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;
        //
        //     return SignerImpl(first, last, std::move(out),
        //                       SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key)))));
        // }

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
        // template<typename Scheme, typename InputIterator, typename KeyInputIterator,
        //          typename SchemeAccumulator = typename pubkey::signing_accumulator_set<typename
        //          pubkey::modes::isomorphic<
        //              Scheme, pubkey::nop_padding>::template bind<pubkey::signing_policy<Scheme>>::type>>
        // pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        //     sign(InputIterator first, InputIterator last, KeyInputIterator key_first, KeyInputIterator key_last) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(first, last,
        //                       SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key_first, key_last)))));
        // }

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
        // template<typename Scheme, typename InputIterator, typename KeySinglePassRange,
        //          typename SchemeAccumulator = typename pubkey::signing_accumulator_set<typename
        //          pubkey::modes::isomorphic<
        //              Scheme, pubkey::nop_padding>::template bind<pubkey::signing_policy<Scheme>>::type>>
        // pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        //     sign(InputIterator first, InputIterator last, const KeySinglePassRange &key) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(first, last, SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key)))));
        // }

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
        // template<typename Scheme, typename SinglePassRange, typename KeySinglePassRange, typename OutputIterator>
        // OutputIterator sign(const SinglePassRange &rng, const KeySinglePassRange &key, OutputIterator out) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //     typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;
        //
        //     return SignerImpl(rng, std::move(out),
        //     SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key)))));
        // }

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
        // template<typename Scheme, typename SinglePassRange, typename KeySinglePassRange, typename OutputRange>
        // OutputRange &sign(const SinglePassRange &rng, const KeySinglePassRange &key, OutputRange &out) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //     typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(rng, std::move(out),
        //     SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key)))));
        // }

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
        // template<typename Scheme, typename SinglePassRange, typename KeySinglePassRange,
        //          typename SchemeAccumulator = typename pubkey::signing_accumulator_set<typename
        //          pubkey::modes::isomorphic<
        //              Scheme, pubkey::nop_padding>::template bind<pubkey::signing_policy<Scheme>>::type>>
        // pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
        //     sign(const SinglePassRange &r, const KeySinglePassRange &key) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(r, SchemeAccumulator(Mode(Scheme(pubkey::private_key<Scheme>(key)))));
        // }

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
        // template<typename Scheme, typename SinglePassRange, typename OutputRange>
        // OutputRange &sign(const SinglePassRange &rng, const pubkey::private_key<Scheme> &key, OutputRange &out) {
        //
        //     typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
        //         pubkey::signing_policy<Scheme>>::type Mode;
        //     typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;
        //
        //     typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
        //     typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;
        //
        //     return SignerImpl(rng, std::move(out), SchemeAccumulator(key));
        // }

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
         *  
         * @param out
         *
         * @return
         */
        template<typename Scheme, typename InputIterator, typename OutputIterator>
        OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key,
                            OutputIterator out) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::signing_policy<Scheme>>::type Mode;
            typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(first, last, std::move(out), SchemeAccumulator(key));
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
            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::signing_policy<Scheme>>::type Mode;
            typedef typename pubkey::signing_accumulator_set<Mode> SchemeAccumulator;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::itr_scheme_impl<StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(rng, std::move(out), SchemeAccumulator(key));
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
        template<
            typename Scheme, typename InputIterator,
            typename OutputAccumulator = typename pubkey::signing_accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::signing_policy<Scheme>>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

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
                 typename OutputAccumulator = typename pubkey::signing_accumulator_set<
                     typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                         typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::signing_policy>::type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            sign(const SinglePassRange &r, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_scheme_impl<OutputAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

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
        template<
            typename Scheme, typename InputIterator,
            typename SchemeAccumulator = typename pubkey::signing_accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::signing_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
            sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::signing_policy<Scheme>>::type Mode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, SchemeAccumulator(key));
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
        template<
            typename Scheme, typename SinglePassRange,
            typename SchemeAccumulator = typename pubkey::signing_accumulator_set<typename pubkey::modes::isomorphic<
                Scheme, pubkey::nop_padding>::template bind<pubkey::signing_policy<Scheme>>::type>>
        pubkey::detail::range_scheme_impl<pubkey::detail::value_scheme_impl<SchemeAccumulator>>
            sign(const SinglePassRange &r, const pubkey::private_key<Scheme> &key) {

            typedef typename pubkey::modes::isomorphic<Scheme, pubkey::nop_padding>::template bind<
                pubkey::signing_policy<Scheme>>::type Mode;

            typedef pubkey::detail::value_scheme_impl<SchemeAccumulator> StreamSignerImpl;
            typedef pubkey::detail::range_scheme_impl<StreamSignerImpl> SignerImpl;

            return SignerImpl(r, SchemeAccumulator(key));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
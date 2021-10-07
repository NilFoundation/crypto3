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

#ifndef CRYPTO3_PUBKEY_MODE_SIGN_HPP
#define CRYPTO3_PUBKEY_MODE_SIGN_HPP

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/modes/pubkey_state.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>

namespace nil {
    namespace crypto3 {
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
                 typename SigningAccumulator = pubkey::weighted_signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(InputIterator first, InputIterator last,
                        typename pubkey::private_key<Scheme>::weights_type &weights,
                        const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(first, last, SigningAccumulator(key, nil::crypto3::accumulators::weights = weights));
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
                 typename SigningAccumulator = pubkey::weighted_signing_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<SigningAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl sign(const SinglePassRange &rng, typename pubkey::private_key<Scheme>::weights_type &weights,
                        const pubkey::private_key<Scheme> &key) {
            return SchemeImpl(rng, SigningAccumulator(key, nil::crypto3::accumulators::weights = weights));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard

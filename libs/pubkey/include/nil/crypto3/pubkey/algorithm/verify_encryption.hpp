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

#ifndef CRYPTO3_PUBKEY_VERIFY_ENCRYPTION_HPP
#define CRYPTO3_PUBKEY_VERIFY_ENCRYPTION_HPP

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>

#include <nil/crypto3/pubkey/pubkey_value.hpp>
#include <nil/crypto3/pubkey/pubkey_state.hpp>

#include <nil/crypto3/pubkey/modes/verifiable_encryption.hpp>

#include <nil/crypto3/pubkey/operations/verify_encryption_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Scheme>
            using encryption_verification_init_params_type = typename verify_encryption_op<Scheme>::init_params_type;
        }

        template<typename Scheme, typename Mode = pubkey::modes::verifiable_encryption<Scheme>,
                 typename ProcessingMode = typename Mode::encryption_verification_policy, typename InputIterator,
                 typename OutputIterator>
        OutputIterator verify_encryption(InputIterator first, InputIterator last,
                                         const pubkey::encryption_verification_init_params_type<Scheme> &init_params,
                                         OutputIterator out) {

            typedef typename pubkey::pubkey_accumulator_set<ProcessingMode> PubkeyAccumulator;

            typedef pubkey::detail::value_pubkey_impl<PubkeyAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), PubkeyAccumulator(init_params));
        }

        template<typename Scheme, typename Mode = pubkey::modes::verifiable_encryption<Scheme>,
                 typename ProcessingMode = typename Mode::encryption_verification_policy, typename SinglePassRange,
                 typename OutputIterator>
        OutputIterator verify_encryption(const SinglePassRange &range,
                                         const pubkey::encryption_verification_init_params_type<Scheme> &init_params,
                                         OutputIterator out) {

            typedef typename pubkey::pubkey_accumulator_set<ProcessingMode> PubkeyAccumulator;

            typedef pubkey::detail::value_pubkey_impl<PubkeyAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::itr_pubkey_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(range, std::move(out), PubkeyAccumulator(init_params));
        }

        template<typename Scheme, typename Mode = pubkey::modes::verifiable_encryption<Scheme>,
                 typename ProcessingMode = typename Mode::encryption_verification_policy, typename InputIterator,
                 typename OutputAccumulator = typename pubkey::pubkey_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            verify_encryption(InputIterator first, InputIterator last, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        template<typename Scheme, typename Mode = pubkey::modes::verifiable_encryption<Scheme>,
                 typename ProcessingMode = typename Mode::encryption_verification_policy, typename SinglePassRange,
                 typename OutputAccumulator = typename pubkey::pubkey_accumulator_set<ProcessingMode>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            verify_encryption(const SinglePassRange &range, OutputAccumulator &acc) {

            typedef pubkey::detail::ref_pubkey_impl<OutputAccumulator> StreamSchemeImpl;
            typedef pubkey::detail::range_pubkey_impl<StreamSchemeImpl> SchemeImpl;

            return SchemeImpl(range, std::forward<OutputAccumulator>(acc));
        }

        template<typename Scheme, typename Mode = pubkey::modes::verifiable_encryption<Scheme>,
                 typename ProcessingMode = typename Mode::encryption_verification_policy, typename InputIterator,
                 typename PubkeyAccumulator = typename pubkey::pubkey_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<PubkeyAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl verify_encryption(InputIterator first, InputIterator last,
                                     const pubkey::encryption_verification_init_params_type<Scheme> &init_params) {

            return SchemeImpl(first, last, PubkeyAccumulator(init_params));
        }

        template<typename Scheme, typename Mode = pubkey::modes::verifiable_encryption<Scheme>,
                 typename ProcessingMode = typename Mode::encryption_verification_policy, typename SinglePassRange,
                 typename PubkeyAccumulator = typename pubkey::pubkey_accumulator_set<ProcessingMode>,
                 typename StreamSchemeImpl = pubkey::detail::value_pubkey_impl<PubkeyAccumulator>,
                 typename SchemeImpl = pubkey::detail::range_pubkey_impl<StreamSchemeImpl>>
        SchemeImpl verify_encryption(const SinglePassRange &range,
                                     const pubkey::encryption_verification_init_params_type<Scheme> &init_params) {

            return SchemeImpl(range, PubkeyAccumulator(init_params));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard

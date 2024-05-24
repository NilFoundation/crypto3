//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MAC_COMPUTE_HPP
#define CRYPTO3_MAC_COMPUTE_HPP

#include <nil/crypto3/mac/mac_value.hpp>
#include <nil/crypto3/mac/mac_state.hpp>
#include <nil/crypto3/mac/mac_key.hpp>
#include <nil/crypto3/mac/mac_processing_policies.hpp>

#include <nil/crypto3/mac/algorithm/mac.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename Mac, template<typename> class Padding = nop_padding>
            using computation_policy = typename processing_policies<Mac, Padding>::computation_policy;
        }

        /*!
         * @brief
         *
         * @tparam Mac
         * @tparam InputIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @param out
         * @return
         */
        template<typename Mac, typename InputIterator, typename OutputIterator>
        OutputIterator compute(InputIterator first, InputIterator last, const mac::mac_key<Mac> &key,
                               OutputIterator out) {
            typedef mac::computation_accumulator_set<mac::computation_policy<Mac>> MacAccumulator;

            typedef mac::detail::value_mac_impl<MacAccumulator> StreamSchemeImpl;
            typedef mac::detail::itr_mac_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(first, last, std::move(out), MacAccumulator(key));
        }

        /*!
         * @brief
         *
         * @tparam Mac
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         * @return
         */
        template<typename Mac, typename SinglePassRange, typename OutputIterator>
        OutputIterator compute(const SinglePassRange &rng, const mac::mac_key<Mac> &key, OutputIterator out) {
            typedef mac::computation_accumulator_set<mac::computation_policy<Mac>> MacAccumulator;

            typedef mac::detail::value_mac_impl<MacAccumulator> StreamSchemeImpl;
            typedef mac::detail::itr_mac_impl<StreamSchemeImpl, OutputIterator> SchemeImpl;

            return SchemeImpl(rng, std::move(out), MacAccumulator(key));
        }

        /*!
         * @brief
         *
         * @tparam Mac
         * @tparam InputIterator
         * @tparam OutputIterator
         *
         * @param first
         * @param last
         * @return
         */
        template<typename Mac, typename InputIterator,
                 typename MacAccumulator = mac::computation_accumulator_set<mac::computation_policy<Mac>>,
                 typename StreamMacImpl = mac::detail::value_mac_impl<MacAccumulator>,
                 typename MacImpl = mac::detail::range_mac_impl<StreamMacImpl>>
        MacImpl compute(InputIterator first, InputIterator last, const mac::mac_key<Mac> &key) {
            return MacImpl(first, last, MacAccumulator(key));
        }

        /*!
         * @brief
         * @tparam Mac
         * @tparam OutputRange
         * @tparam SinglePassRange
         * @param rng
         * @return
         */
        template<typename Mac, typename SinglePassRange,
                 typename MacAccumulator = mac::computation_accumulator_set<mac::computation_policy<Mac>>,
                 typename StreamMacImpl = mac::detail::value_mac_impl<MacAccumulator>,
                 typename MacImpl = mac::detail::range_mac_impl<StreamMacImpl>>
        MacImpl compute(const SinglePassRange &rng, const mac::mac_key<Mac> &key) {
            return MacImpl(rng, MacAccumulator(key));
        }

        /*!
         * @brief
         *
         * @ingroup mac_algorithms
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
        template<typename Mac, typename InputIterator,
                 typename OutputAccumulator = mac::computation_accumulator_set<mac::computation_policy<Mac>>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            compute(InputIterator first, InputIterator last, OutputAccumulator &acc) {
            typedef mac::detail::ref_mac_impl<OutputAccumulator> StreamMacImpl;
            typedef mac::detail::range_mac_impl<StreamMacImpl> MacImpl;

            return MacImpl(first, last, std::forward<OutputAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup mac_algorithms
         *
         * @tparam Mac
         * @tparam SinglePassRange
         * @tparam EncodingPolicy
         * @tparam OutputAccumulator
         *
         * @param r
         * @param acc
         *
         * @return
         */
        template<typename Mac, typename SinglePassRange,
                 typename OutputAccumulator = mac::computation_accumulator_set<mac::computation_policy<Mac>>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                                OutputAccumulator>::type &
            compute(const SinglePassRange &r, OutputAccumulator &acc) {
            typedef mac::detail::ref_mac_impl<OutputAccumulator> StreamMacImpl;
            typedef mac::detail::range_mac_impl<StreamMacImpl> MacImpl;

            return MacImpl(r, std::forward<OutputAccumulator>(acc));
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_COMPUTE_HPP

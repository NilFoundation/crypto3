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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SSS_DEAL_SHARE_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SSS_DEAL_SHARE_HPP

#include <set>
#include <utility>
#include <algorithm>
#include <iterator>

#include <boost/concept_check.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/threshold_value.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/iterator_last.hpp>

#include <nil/crypto3/pubkey/secret_sharing.hpp>
#include <nil/crypto3/pubkey/dkg.hpp>

#include <nil/crypto3/pubkey/detail/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace accumulators {
                namespace impl {
                    template<typename ProcessingMode, typename = void>
                    struct deal_share_impl;

                    template<typename ProcessingMode>
                    struct deal_share_impl<
                        ProcessingMode,
                        typename std::enable_if<
                            std::is_same<typename ProcessingMode::scheme_type,
                                         pubkey::pedersen_dkg<typename ProcessingMode::scheme_type::group_type>>::value>::type>
                        : boost::accumulators::accumulator_base {
                        typedef typename ProcessingMode::scheme_type scheme_type;
                        typedef typename ProcessingMode::key_type key_type;

                        typedef typename key_type::private_element_type private_element_type;
                        typedef typename key_type::share_type share_type;
                        typedef typename key_type::shares_type shares_type;

                    public:
                        typedef share_type result_type;

                        //
                        // boost::accumulators::sample -- participant index
                        //
                        template<typename Args>
                        deal_share_impl(const Args &args) {
                            share = share_type(0, private_element_type::zero());
                        }

                        inline result_type result(boost::accumulators::dont_care) const {
                            return share;
                        }

                        //
                        // boost::accumulators::sample -- polynomial coefficients
                        // input coefficients should be supplied in increasing term degrees order
                        //
                        template<typename Args>
                        inline void operator()(const Args &args) {
                            resolve_type(
                                args[boost::accumulators::sample],
                                args[::nil::crypto3::accumulators::iterator_last | typename shares_type::iterator()]);
                        }

                    protected:
                        template<typename Share,
                                 typename InputIterator,
                                 typename key_type::template check_share_type<Share> = true>
                        inline void resolve_type(const Share &share_update, InputIterator) {
                            if (!share.first) {
                                assert(key_type::check_participant_index(share_update.first));
                                share.first = share_update.first;
                            }

                            assert(share_update.first == share.first);
                            share.second = share.second + share_update.second;
                        }

                        template<typename Shares,
                                 typename InputIterator,
                                 typename key_type::template check_shares_type<Shares> = true>
                        inline void resolve_type(const Shares &shares_update, InputIterator dont_care) {
                            for (const auto &s : shares_update) {
                                resolve_type(s, dont_care);
                            }
                        }

                        template<typename InputIterator,
                                 typename key_type::template check_share_type<
                                     typename std::iterator_traits<InputIterator>::value_type> = true>
                        inline void resolve_type(InputIterator first, InputIterator last) {
                            for (auto it = first; it != last; it++) {
                                resolve_type(*it, last);
                            }
                        }

                        result_type share;
                    };
                }    // namespace impl

                namespace tag {
                    template<typename ProcessingMode>
                    struct deal_share : boost::accumulators::depends_on<> {
                        typedef ProcessingMode mode_type;

                        /// INTERNAL ONLY
                        ///

                        typedef boost::mpl::always<accumulators::impl::deal_share_impl<mode_type>> impl;
                    };
                }    // namespace tag

                namespace extract {
                    template<typename ProcessingMode, typename AccumulatorSet>
                    typename boost::mpl::apply<AccumulatorSet, tag::deal_share<ProcessingMode>>::type::result_type
                        deal_share(const AccumulatorSet &acc) {
                        return boost::accumulators::extract_result<tag::deal_share<ProcessingMode>>(acc);
                    }
                }    // namespace extract
            }        // namespace accumulators
        }            // namespace pubkey
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SSS_DEAL_SHARE_HPP

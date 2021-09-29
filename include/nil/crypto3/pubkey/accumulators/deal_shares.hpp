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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SSS_DEAL_SHARES_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SSS_DEAL_SHARES_HPP

#include <cstddef>
#include <set>
#include <utility>
#include <algorithm>
#include <iterator>

#include <boost/concept_check.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/threshold_value.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/iterator_last.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/weights.hpp>

#include <nil/crypto3/pubkey/secret_sharing/shamir.hpp>
#include <nil/crypto3/pubkey/secret_sharing/feldman.hpp>
#include <nil/crypto3/pubkey/secret_sharing/pedersen.hpp>
#include <nil/crypto3/pubkey/secret_sharing/weighted_shamir.hpp>

#include <nil/crypto3/pubkey/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace accumulators {
                namespace impl {
                    template<typename ProcessingMode, typename = void>
                    struct deal_shares_impl;

                    template<typename ProcessingMode>
                    struct deal_shares_impl<ProcessingMode> : boost::accumulators::accumulator_base {
                    protected:
                        typedef ProcessingMode processing_mode_type;
                        typedef typename processing_mode_type::scheme_type scheme_type;
                        typedef typename processing_mode_type::op_type op_type;
                        typedef typename processing_mode_type::internal_accumulator_type internal_accumulator_type;

                    public:
                        typedef typename processing_mode_type::result_type result_type;

                        //
                        // boost::accumulators::sample -- participants number
                        //
                        // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                        //
                        template<typename Args>
                        deal_shares_impl(const Args &args) :
                            seen_coeffs(0), n(args[boost::accumulators::sample]),
                            t(args[nil::crypto3::accumulators::threshold_value]) {
                            if constexpr (std::is_same<weighted_shamir_sss<typename scheme_type::group_type>,
                                                       scheme_type>::value) {
                                processing_mode_type::init_accumulator(
                                    acc, n, t, args[nil::crypto3::accumulators::weights]);
                            } else {
                                processing_mode_type::init_accumulator(acc, n, t);
                            }
                        }

                        inline result_type result(boost::accumulators::dont_care) const {
                            assert(t == seen_coeffs);

                            return processing_mode_type::process(acc);
                        }

                        //
                        // boost::accumulators::sample -- polynomial coefficients
                        // input coefficients should be supplied in increasing term degrees order
                        //
                        template<typename Args>
                        inline void operator()(const Args &args) {
                            resolve_type(args[boost::accumulators::sample],
                                         args[::nil::crypto3::accumulators::iterator_last | nullptr]);
                        }

                    protected:
                        inline void resolve_type(const typename scheme_type::coeff_type &coeff,
                                                 std::nullptr_t = nullptr) {
                            if (t == seen_coeffs) {
                                return;
                            }

                            processing_mode_type::update(acc, seen_coeffs, coeff);
                            seen_coeffs++;
                        }

                        template<typename InputRange>
                        inline void resolve_type(const InputRange &range, std::nullptr_t) {
                            for (const auto &c : range) {
                                resolve_type(c);
                            }
                        }

                        template<typename InputIterator>
                        inline void resolve_type(InputIterator first, InputIterator last) {
                            for (auto it = first; it != last; it++) {
                                resolve_type(*it);
                            }
                        }

                        std::size_t n;
                        std::size_t t;
                        std::size_t seen_coeffs;
                        mutable internal_accumulator_type acc;
                    };

                    // template<typename ProcessingMode>
                    // struct deal_shares_impl<
                    //     ProcessingMode,
                    //     typename std::enable_if<std::is_same<
                    //         typename ProcessingMode::scheme_type,
                    //         pubkey::weighted_shamir_sss<typename
                    //         ProcessingMode::scheme_type::group_type>>::value>::type>
                    //     : boost::accumulators::accumulator_base {
                    // protected:
                    //     typedef typename ProcessingMode::scheme_type scheme_type;
                    //     typedef typename ProcessingMode::op_type op_type;
                    //
                    //     typedef typename op_type::coeffs_type coeffs_type;
                    //     typedef typename op_type::weight_type weight_type;
                    //     typedef typename op_type::weights_type weights_type;
                    //     typedef typename op_type::shares_type shares_type;
                    //
                    // public:
                    //     typedef shares_type result_type;
                    //
                    //     //
                    //     // boost::accumulators::sample -- participants number
                    //     //
                    //     // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                    //     //
                    //     template<typename Args>
                    //     deal_shares_impl(const Args &args) : seen_coeffs(0) {
                    //         assert(op_type::check_t(args[nil::crypto3::accumulators::threshold_value],
                    //                                  args[boost::accumulators::sample]));
                    //         t = args[nil::crypto3::accumulators::threshold_value];
                    //         n = args[boost::accumulators::sample];
                    //         std::size_t i = 1;
                    //         std::generate_n(std::inserter(shares_weights, shares_weights.end()), n, [&i]() {
                    //             return weight_type(i++, 1);
                    //         });
                    //     }
                    //
                    //     inline result_type result(boost::accumulators::dont_care) const {
                    //         assert(t == seen_coeffs);
                    //         return op_type::deal_shares(coeffs, shares_weights);
                    //     }
                    //
                    //     //
                    //     // boost::accumulators::sample -- participant weight
                    //     // or
                    //     // boost::accumulators::sample -- polynomial coefficients
                    //     // input coefficients should be supplied in increasing term degrees order
                    //     //
                    //     template<typename Args>
                    //     inline void operator()(const Args &args) {
                    //         resolve_type(
                    //             args[boost::accumulators::sample],
                    //             args[::nil::crypto3::accumulators::iterator_last | typename
                    //             coeffs_type::iterator()]);
                    //     }
                    //
                    // protected:
                    //     template<typename Coeff,
                    //              typename InputIterator,
                    //              typename op_type::template check_coeff_type<Coeff> = true>
                    //     inline void resolve_type(const Coeff &coeff, InputIterator) {
                    //         assert(t > seen_coeffs);
                    //         coeffs.emplace_back(coeff);
                    //         seen_coeffs++;
                    //     }
                    //
                    //     template<typename Coeffs,
                    //              typename InputIterator,
                    //              typename op_type::template check_coeff_type<typename Coeffs::value_type> = true>
                    //     inline void resolve_type(const Coeffs &coeffs, InputIterator dont_care) {
                    //         for (const auto &c : coeffs) {
                    //             resolve_type(c, dont_care);
                    //         }
                    //     }
                    //
                    //     template<typename InputIterator,
                    //              typename op_type::template check_coeff_type<
                    //                  typename std::iterator_traits<InputIterator>::value_type> = true>
                    //     inline void resolve_type(InputIterator first, InputIterator last) {
                    //         for (auto it = first; it != last; it++) {
                    //             resolve_type(*it, last);
                    //         }
                    //     }
                    //
                    //     template<typename Weight,
                    //              typename InputIterator,
                    //              typename op_type::template check_weight_type<Weight> = true>
                    //     inline void resolve_type(const Weight &w, InputIterator) {
                    //         assert(op_type::check_weight(w, n));
                    //         shares_weights.insert_or_assign(w.first, w.second);
                    //     }
                    //
                    //     template<typename InputIterator,
                    //              typename op_type::template check_weight_type<
                    //                  typename std::iterator_traits<InputIterator>::value_type> = true>
                    //     inline void resolve_type(InputIterator first, InputIterator last) {
                    //         for (auto it = first; it != last; it++) {
                    //             resolve_type(*it, last);
                    //         }
                    //     }
                    //
                    //     std::size_t t;
                    //     std::size_t n;
                    //     std::size_t seen_coeffs;
                    //     coeffs_type coeffs;
                    //     weights_type shares_weights;
                    // };
                }    // namespace impl

                namespace tag {
                    template<typename ProcessingMode>
                    struct deal_shares : boost::accumulators::depends_on<> {
                        typedef ProcessingMode mode_type;

                        /// INTERNAL ONLY
                        ///

                        typedef boost::mpl::always<accumulators::impl::deal_shares_impl<mode_type>> impl;
                    };
                }    // namespace tag

                namespace extract {
                    template<typename ProcessingMode, typename AccumulatorSet>
                    typename boost::mpl::apply<AccumulatorSet, tag::deal_shares<ProcessingMode>>::type::result_type
                        deal_shares(const AccumulatorSet &acc) {
                        return boost::accumulators::extract_result<tag::deal_shares<ProcessingMode>>(acc);
                    }
                }    // namespace extract
            }        // namespace accumulators
        }            // namespace pubkey
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SSS_DEAL_SHARES_HPP

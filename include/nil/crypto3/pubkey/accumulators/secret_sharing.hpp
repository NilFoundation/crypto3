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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SSS_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SSS_HPP

#include <set>
#include <utility>
#include <algorithm>
#include <iterator>

#include <boost/concept_check.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/threshold_value.hpp>

#include <nil/crypto3/pubkey/detail/secret_sharing/weighted_shamir.hpp>
#include <nil/crypto3/pubkey/detail/secret_sharing/feldman.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Scheme>
                struct deal_shares_impl;

                template<typename Group>
                struct deal_shares_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> :
                    boost::accumulators::accumulator_base {
                protected:
                    typedef nil::crypto3::pubkey::detail::shamir_sss<Group> scheme_type;

                    typedef typename scheme_type::private_element_type private_element_type;

                    typedef typename scheme_type::coeff_type coeff_type;
                    typedef typename scheme_type::share_type share_type;
                    typedef typename scheme_type::shares_type shares_type;

                public:
                    typedef shares_type result_type;

                    //
                    // boost::accumulators::sample -- participants number
                    //
                    // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                    //
                    template<typename Args>
                    deal_shares_impl(const Args &args) : seen_coeffs(0) {
                        assert(scheme_type::check_t(args[nil::crypto3::accumulators::threshold_value],
                                                    args[boost::accumulators::sample]));
                        n = args[boost::accumulators::sample];
                        t = args[nil::crypto3::accumulators::threshold_value];
                        std::size_t i = 1;
                        std::generate_n(std::inserter(shares, shares.end()), n, [&i]() {
                            return share_type(i++, private_element_type::zero());
                        });
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        assert(t == seen_coeffs);
                        return shares;
                    }

                    //
                    // boost::accumulators::sample -- polynomial coefficients
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                protected:
                    inline void resolve_type(const coeff_type &coeff) {
                        assert(t > seen_coeffs);
                        auto shares_it = shares.begin();
                        private_element_type e_i = private_element_type::one();
                        while (shares_it != shares.end()) {
                            shares_it->second = scheme_type::partial_eval_share(
                                coeff, seen_coeffs, *shares_it).second;
                            shares_it++;
                        }
                        seen_coeffs++;
                    }

                    result_type shares;
                    std::size_t n;
                    std::size_t t;
                    std::size_t seen_coeffs;
                };

                template<typename Group>
                struct deal_shares_impl<nil::crypto3::pubkey::detail::feldman_sss<Group>> : deal_shares_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> {
                    typedef deal_shares_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> base_type;
                    //
                    // boost::accumulators::sample -- participants number
                    //
                    // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                    //
                    template<typename Args>
                    deal_shares_impl(const Args &args) : base_type(args) {}
                };



                template<typename Group>
                struct deal_shares_impl<nil::crypto3::pubkey::detail::weighted_shamir_sss<Group>> :
                    boost::accumulators::accumulator_base {
                protected:
                    typedef nil::crypto3::pubkey::detail::weighted_shamir_sss<Group> scheme_type;

                    typedef typename scheme_type::private_element_type private_element_type;
                    typedef typename scheme_type::coeff_type coeff_type;
                    typedef typename scheme_type::coeffs_type coeffs_type;
                    typedef typename scheme_type::weight_type weight_type;
                    typedef typename scheme_type::weights_type weights_type;
                    typedef typename scheme_type::share_type share_type;
                    typedef typename scheme_type::shares_type shares_type;

                public:
                    typedef shares_type result_type;

                    //
                    // boost::accumulators::sample -- participants number
                    //
                    // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                    //
                    template<typename Args>
                    deal_shares_impl(const Args &args) : seen_coeffs(0) {
                        assert(scheme_type::check_t(args[nil::crypto3::accumulators::threshold_value],
                                                    args[boost::accumulators::sample]));
                        t = args[nil::crypto3::accumulators::threshold_value];
                        n = args[boost::accumulators::sample];
                        std::size_t i = 1;
                        std::generate_n(std::inserter(shares_weights, shares_weights.end()), n, [&i]() {
                            return weight_type(i++, 1);
                        });
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        assert(t == seen_coeffs);
                        return scheme_type::deal_shares(coeffs, shares_weights);
                    }

                    //
                    // boost::accumulators::sample -- participant weight
                    // or
                    // boost::accumulators::sample -- polynomial coefficients
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                protected:
                    inline void resolve_type(const coeff_type &coeff) {
                        assert(t > seen_coeffs);
                        coeffs.emplace_back(coeff);
                        seen_coeffs++;
                    }

                    template<typename Weight,
                             typename scheme_type::template check_indexed_weight_type<Weight> = true>
                    inline void resolve_type(const Weight &w_i) {
                        assert(0 < w_i.first && w_i.first <= n);
                        assert(scheme_type::check_weight(w_i.second));
                        shares_weights.insert_or_assign(w_i.first, w_i.second);
                    }

                    std::size_t t;
                    std::size_t n;
                    std::size_t seen_coeffs;
                    coeffs_type coeffs;
                    weights_type shares_weights;
                };

                template<typename Scheme>
                struct reconstruct_secret_impl;

                template<typename Group>
                struct reconstruct_secret_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>>:
                    boost::accumulators::accumulator_base {
                protected:
                    typedef nil::crypto3::pubkey::detail::shamir_sss<Group> scheme_type;

                    typedef typename scheme_type::private_element_type private_element_type;
                    typedef typename scheme_type::share_type share_type;
                    typedef typename scheme_type::shares_type shares_type;

                public:
                    typedef private_element_type result_type;

                    template<typename Args>
                    reconstruct_secret_impl(const Args &args) : seen_shares(0) {
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        assert(scheme_type::check_minimal_size(seen_shares));
                        return scheme_type::reconstruct_secret(shares);
                    }

                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                protected:
                    inline void resolve_type(const share_type &share) {
                        assert(shares.emplace(share).second);
                        seen_shares++;
                    }

                    std::size_t seen_shares;
                    shares_type shares;
                };

                template<typename Group>
                struct reconstruct_secret_impl<nil::crypto3::pubkey::detail::weighted_shamir_sss<Group>> :
                    reconstruct_secret_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> {
                    typedef reconstruct_secret_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> base_type;

                    template<typename Args>
                    reconstruct_secret_impl(const Args &args) : base_type(args) {}
                };

                template<typename Group>
                struct reconstruct_secret_impl<nil::crypto3::pubkey::detail::feldman_sss<Group>> :
                    reconstruct_secret_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> {
                    typedef reconstruct_secret_impl<nil::crypto3::pubkey::detail::shamir_sss<Group>> base_type;

                    template<typename Args>
                    reconstruct_secret_impl(const Args &args) : base_type(args) {}
                };

                template<typename Scheme>
                struct verify_share_impl;

                template<typename Group>
                struct verify_share_impl<nil::crypto3::pubkey::detail::feldman_sss<Group>>:
                    boost::accumulators::accumulator_base {
                protected:
                    typedef nil::crypto3::pubkey::detail::feldman_sss<Group> scheme_type;

                    typedef typename scheme_type::public_element_type public_element_type;
                    typedef typename scheme_type::public_coeff_type public_coeff_type;
                    typedef typename scheme_type::public_share_type public_share_type;

                public:
                    typedef bool result_type;

                    //
                    // boost::accumulators::sample -- verified public share
                    //
                    template<typename Args>
                    verify_share_impl(const Args &args) :
                        public_share(args[boost::accumulators::sample]), seen_coeffs(0),
                        verification_value(public_share.first, public_element_type::zero()) {
                    }

                    //
                    // boost::accumulators::sample -- public polynomial coefficients
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return public_share == verification_value;
                    }

                protected:
                    inline void resolve_type(const public_coeff_type &public_coeff) {
                        verification_value = scheme_type::partial_eval_verification_value(
                            public_coeff, seen_coeffs, verification_value);
                        seen_coeffs++;
                    }

                    public_share_type public_share;
                    public_share_type verification_value;
                    std::size_t seen_coeffs;
                };
            }    // namespace impl

            namespace tag {
                template<typename Scheme>
                struct deal_shares : boost::accumulators::depends_on<> {
                    typedef Scheme scheme_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::deal_shares_impl<scheme_type>> impl;
                };

                template<typename Scheme>
                struct verify_share : boost::accumulators::depends_on<> {
                    typedef Scheme scheme_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::verify_share_impl<scheme_type>> impl;
                };

                template<typename Scheme>
                struct reconstruct_secret : boost::accumulators::depends_on<> {
                    typedef Scheme scheme_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::reconstruct_secret_impl<scheme_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Scheme, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::deal_shares<Scheme>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::deal_shares<Scheme>>(acc);
                }

                template<typename Scheme, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::verify_share<Scheme>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::verify_share<Scheme>>(acc);
                }

                template<typename Scheme, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::reconstruct_secret<Scheme>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::reconstruct_secret<Scheme>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SSS_HPP

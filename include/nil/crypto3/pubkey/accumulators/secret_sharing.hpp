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
#include <nil/crypto3/pubkey/accumulators/parameters/iterator_last.hpp>

#include <nil/crypto3/pubkey/secret_sharing.hpp>

#include <nil/crypto3/pubkey/detail/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode, typename = void>
                struct deal_shares_impl;

                template<typename Mode>
                struct deal_shares_impl<
                    Mode,
                    typename std::enable_if<
                        std::is_same<typename Mode::scheme_type,
                                     pubkey::shamir_sss<typename Mode::scheme_type::group_type>>::value ||
                        std::is_same<typename Mode::scheme_type,
                                     pubkey::feldman_sss<typename Mode::scheme_type::group_type>>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef typename Mode::scheme_type scheme_type;
                    typedef typename Mode::key_type key_type;

                    typedef typename key_type::private_element_type private_element_type;
                    typedef typename key_type::share_type share_type;
                    typedef typename key_type::shares_type shares_type;
                    typedef typename key_type::coeffs_type coeffs_type;

                public:
                    typedef shares_type result_type;

                    //
                    // boost::accumulators::sample -- participants number
                    //
                    // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                    //
                    template<typename Args>
                    deal_shares_impl(const Args &args) : seen_coeffs(0) {
                        assert(key_type::check_t(args[nil::crypto3::accumulators::threshold_value],
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
                        resolve_type(
                            args[boost::accumulators::sample],
                            args[::nil::crypto3::accumulators::iterator_last | typename coeffs_type::iterator()]);
                    }

                protected:
                    template<typename Coeff,
                             typename InputIterator,
                             typename key_type::template check_coeff_type<Coeff> = true>
                    inline void resolve_type(const Coeff &coeff, InputIterator) {
                        assert(t > seen_coeffs);
                        auto shares_it = shares.begin();
                        private_element_type e_i = private_element_type::one();
                        while (shares_it != shares.end()) {
                            shares_it->second = key_type::partial_eval_share(coeff, seen_coeffs, *shares_it).second;
                            shares_it++;
                        }
                        seen_coeffs++;
                    }

                    template<typename Coeffs,
                             typename InputIterator,
                             typename key_type::template check_coeff_type<typename Coeffs::value_type> = true>
                    inline void resolve_type(const Coeffs &coeffs, InputIterator dont_care) {
                        for (const auto &c : coeffs) {
                            resolve_type(c, dont_care);
                        }
                    }

                    template<typename InputIterator,
                             typename key_type::template check_coeff_type<
                                 typename std::iterator_traits<InputIterator>::value_type> = true>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        for (auto it = first; it != last; it++) {
                            resolve_type(*it, last);
                        }
                    }

                    result_type shares;
                    std::size_t n;
                    std::size_t t;
                    std::size_t seen_coeffs;
                };

                template<typename Mode>
                struct deal_shares_impl<
                    Mode,
                    typename std::enable_if<
                        std::is_same<typename Mode::scheme_type,
                                     pubkey::weighted_shamir_sss<typename Mode::scheme_type::group_type>>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef typename Mode::scheme_type scheme_type;
                    typedef typename Mode::key_type key_type;

                    typedef typename key_type::coeffs_type coeffs_type;
                    typedef typename key_type::weight_type weight_type;
                    typedef typename key_type::weights_type weights_type;
                    typedef typename key_type::shares_type shares_type;

                public:
                    typedef shares_type result_type;

                    //
                    // boost::accumulators::sample -- participants number
                    //
                    // nil::crypto3::accumulators::threshold_value -- threshold number of participants
                    //
                    template<typename Args>
                    deal_shares_impl(const Args &args) : seen_coeffs(0) {
                        assert(key_type::check_t(args[nil::crypto3::accumulators::threshold_value],
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
                        return key_type::deal_shares(coeffs, shares_weights);
                    }

                    //
                    // boost::accumulators::sample -- participant weight
                    // or
                    // boost::accumulators::sample -- polynomial coefficients
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(
                            args[boost::accumulators::sample],
                            args[::nil::crypto3::accumulators::iterator_last | typename coeffs_type::iterator()]);
                    }

                protected:
                    template<typename Coeff,
                             typename InputIterator,
                             typename key_type::template check_coeff_type<Coeff> = true>
                    inline void resolve_type(const Coeff &coeff, InputIterator) {
                        assert(t > seen_coeffs);
                        coeffs.emplace_back(coeff);
                        seen_coeffs++;
                    }

                    template<typename Coeffs,
                             typename InputIterator,
                             typename key_type::template check_coeff_type<typename Coeffs::value_type> = true>
                    inline void resolve_type(const Coeffs &coeffs, InputIterator dont_care) {
                        for (const auto &c : coeffs) {
                            resolve_type(c, dont_care);
                        }
                    }

                    template<typename InputIterator,
                             typename key_type::template check_coeff_type<
                                 typename std::iterator_traits<InputIterator>::value_type> = true>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        for (auto it = first; it != last; it++) {
                            resolve_type(*it, last);
                        }
                    }

                    template<typename Weight,
                             typename InputIterator,
                             typename key_type::template check_weight_type<Weight> = true>
                    inline void resolve_type(const Weight &w, InputIterator) {
                        assert(key_type::check_weight(w, n));
                        shares_weights.insert_or_assign(w.first, w.second);
                    }

                    std::size_t t;
                    std::size_t n;
                    std::size_t seen_coeffs;
                    coeffs_type coeffs;
                    weights_type shares_weights;
                };

                template<typename Mode, typename = void>
                struct reconstruct_secret_impl;

                template<typename Mode>
                struct reconstruct_secret_impl<
                    Mode,
                    typename std::enable_if<
                        std::is_same<typename Mode::scheme_type,
                                     pubkey::shamir_sss<typename Mode::scheme_type::group_type>>::value ||
                        std::is_same<typename Mode::scheme_type,
                                     pubkey::feldman_sss<typename Mode::scheme_type::group_type>>::value ||
                        std::is_same<
                            typename Mode::scheme_type,
                            pubkey::detail::weighted_shamir_sss<typename Mode::scheme_type::group_type>>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef typename Mode::scheme_type scheme_type;
                    typedef typename Mode::key_type key_type;

                    typedef typename key_type::private_element_type private_element_type;
                    typedef typename key_type::shares_type shares_type;

                public:
                    typedef private_element_type result_type;

                    template<typename Args>
                    reconstruct_secret_impl(const Args &args) : seen_shares(0) {
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        assert(key_type::check_minimal_size(seen_shares));
                        return key_type::reconstruct_secret(shares);
                    }

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
                    inline void resolve_type(const Share &share, InputIterator) {
                        assert(shares.emplace(share).second);
                        seen_shares++;
                    }

                    template<typename Shares,
                             typename InputIterator,
                             typename key_type::template check_shares_type<Shares> = true>
                    inline void resolve_type(const Shares &shares, InputIterator dont_care) {
                        for (const auto &s : shares) {
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

                    std::size_t seen_shares;
                    shares_type shares;
                };

                template<typename Mode, typename = void>
                struct verify_share_impl;

                template<typename Mode>
                struct verify_share_impl<Mode,
                                         typename std::enable_if<std::is_same<
                                             typename Mode::scheme_type,
                                             pubkey::feldman_sss<typename Mode::scheme_type::group_type>>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef typename Mode::scheme_type scheme_type;
                    typedef typename Mode::key_type key_type;

                    typedef typename key_type::public_element_type public_element_type;
                    typedef typename key_type::public_coeff_type public_coeff_type;
                    typedef typename key_type::public_coeffs_type public_coeffs_type;
                    typedef typename key_type::public_share_type public_share_type;

                public:
                    typedef bool result_type;

                    //
                    // boost::accumulators::sample -- verified public share
                    //
                    template<typename Args>
                    verify_share_impl(const Args &args) :
                        public_share(key_type::get_public_share(args[boost::accumulators::sample])), seen_coeffs(0),
                        verification_value(public_share.first, public_element_type::zero()) {
                    }

                    //
                    // boost::accumulators::sample -- public polynomial coefficients
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::iterator_last |
                                          typename public_coeffs_type::iterator()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return public_share == verification_value;
                    }

                protected:
                    template<typename PublicCoeff, typename InputIterator,
                             typename key_type::template check_public_coeff_type<PublicCoeff> = true>
                    inline void resolve_type(const PublicCoeff &public_coeff, InputIterator) {
                        verification_value =
                            key_type::partial_eval_verification_value(public_coeff, seen_coeffs, verification_value);
                        seen_coeffs++;
                    }

                    template<typename PublicCoeffs,
                        typename InputIterator,
                        typename key_type::template check_public_coeff_type<typename PublicCoeffs::value_type> = true>
                    inline void resolve_type(const PublicCoeffs &public_coeffs, InputIterator dont_care) {
                        for (const auto &pc : public_coeffs) {
                            resolve_type(pc, dont_care);
                        }
                    }

                    template<typename InputIterator,
                        typename key_type::template check_public_coeff_type<
                            typename std::iterator_traits<InputIterator>::value_type> = true>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        for (auto it = first; it != last; it++) {
                            resolve_type(*it, last);
                        }
                    }

                    public_share_type public_share;
                    public_share_type verification_value;
                    std::size_t seen_coeffs;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct deal_shares : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::deal_shares_impl<mode_type>> impl;
                };

                template<typename Mode>
                struct verify_share : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::verify_share_impl<mode_type>> impl;
                };

                template<typename Mode>
                struct reconstruct_secret : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::reconstruct_secret_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::deal_shares<Mode>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::deal_shares<Mode>>(acc);
                }

                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::verify_share<Mode>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::verify_share<Mode>>(acc);
                }

                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::reconstruct_secret<Mode>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::reconstruct_secret<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SSS_HPP

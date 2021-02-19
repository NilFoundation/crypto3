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

#include <algorithm>
#include <iterator>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Scheme>
                struct deal_shares_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Scheme scheme_type;

                    typedef typename scheme_type::private_elements_type private_elements_type;
                    typedef typename scheme_type::private_element_type private_element_type;

                public:
                    typedef private_elements_type result_type;

                    template<typename Args>
                    deal_shares_impl(const Args &args) : n(args[boost::accumulators::sample]), seen_coeffs(0) {
                        assert(n >= 2);
                        std::fill_n(std::back_inserter(shares), n, private_element_type::zero());
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        assert(scheme_type::check_t(seen_coeffs, n));
                        return shares;
                    }

                    //
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                protected:
                    inline void resolve_type(const private_element_type &coeff) {
                        auto shares_it = shares.begin();
                        std::size_t i = 1;
                        private_element_type e_i = private_element_type::one();
                        while (shares_it != shares.end()) {
                            *shares_it = scheme_type::eval_partial_share(coeff, i++, seen_coeffs, *shares_it);
                            ++shares_it;
                        }
                        seen_coeffs++;
                    }

                    std::size_t n;
                    std::size_t seen_coeffs;
                    result_type shares;
                };

                // template<typename Scheme>
                // struct recover_secret_impl : boost::accumulators::accumulator_base {
                // protected:
                //     typedef Scheme scheme_type;
                //     typedef typename scheme_type::scalar_modulus_type number_type;
                //
                // public:
                //     typedef typename scheme_type::secret_type result_type;
                //
                //     template<typename Args>
                //     recover_secret_impl(const Args &args) :
                //         group_len(args[boost::accumulators::sample]), seen_shares(0), acc_value(0) {
                //     }
                //
                //     inline result_type result(boost::accumulators::dont_care) const {
                //         assert(seen_shares >= t);
                //         return acc_value;
                //     }
                //
                //     template<typename Args>
                //     inline void operator()(const Args &args) {
                //         resolve_type(args[boost::accumulators::sample]);
                //     }
                //
                // protected:
                //     inline void resolve_type(const result_type &share) {
                //         acc_value = scheme_type::recover_secret();
                //         seen_shares++;
                //     }
                //
                //     result_type acc_value;
                //     std::size_t group_len;
                //     std::size_t seen_shares;
                // };

                template<typename Scheme>
                struct verify_share_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Scheme scheme_type;

                    typedef typename scheme_type::public_element_type public_element_type;
                    typedef typename scheme_type::public_elements_type public_elements_type;
                    typedef typename scheme_type::indexed_public_element_type indexed_public_element_type;

                public:
                    typedef bool result_type;

                    template<typename Args>
                    verify_share_impl(const Args &args) :
                        gs_i(args[boost::accumulators::sample]), seen_coeffs(0),
                        share_verification(public_element_type::zero()) {
                    }

                    //
                    // input coefficients should be supplied in increasing term degrees order
                    //
                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return gs_i.second == share_verification;
                    }

                protected:
                    inline void resolve_type(const public_element_type &public_coeff) {
                        share_verification = scheme_type::eval_partial_verification_value(
                            public_coeff, gs_i.first, seen_coeffs, share_verification);
                        seen_coeffs++;
                    }

                    std::size_t seen_coeffs;
                    indexed_public_element_type gs_i;
                    public_element_type share_verification;
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

            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SSS_HPP

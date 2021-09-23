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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_SSS_VERIFY_SHARE_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_SSS_VERIFY_SHARE_HPP

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
                    struct verify_share_impl;

                    template<typename ProcessingMode>
                    struct verify_share_impl<
                        ProcessingMode,
                        typename std::enable_if<
                            std::is_same<typename ProcessingMode::scheme_type,
                                         pubkey::feldman_sss<typename ProcessingMode::scheme_type::group_type>>::value ||
                            std::is_same<typename ProcessingMode::scheme_type,
                                         pubkey::pedersen_dkg<typename ProcessingMode::scheme_type::group_type>>::value>::type>
                        : boost::accumulators::accumulator_base {
                    protected:
                        typedef typename ProcessingMode::scheme_type scheme_type;
                        typedef typename ProcessingMode::key_type key_type;

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
                        template<typename PublicCoeff,
                                 typename InputIterator,
                                 typename key_type::template check_public_coeff_type<PublicCoeff> = true>
                        inline void resolve_type(const PublicCoeff &public_coeff, InputIterator) {
                            verification_value = key_type::partial_eval_verification_value(
                                public_coeff, seen_coeffs, verification_value);
                            seen_coeffs++;
                        }

                        template<typename PublicCoeffs,
                                 typename InputIterator,
                                 typename key_type::template check_public_coeff_type<
                                     typename PublicCoeffs::value_type> = true>
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
                    template<typename ProcessingMode>
                    struct verify_share : boost::accumulators::depends_on<> {
                        typedef ProcessingMode mode_type;

                        /// INTERNAL ONLY
                        ///

                        typedef boost::mpl::always<accumulators::impl::verify_share_impl<mode_type>> impl;
                    };
                }    // namespace tag

                namespace extract {
                    template<typename ProcessingMode, typename AccumulatorSet>
                    typename boost::mpl::apply<AccumulatorSet, tag::verify_share<ProcessingMode>>::type::result_type
                        verify_share(const AccumulatorSet &acc) {
                        return boost::accumulators::extract_result<tag::verify_share<ProcessingMode>>(acc);
                    }
                }    // namespace extract
            }        // namespace accumulators
        }            // namespace pubkey
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_SSS_VERIFY_SHARE_HPP

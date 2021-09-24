//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_FELDMAN_SSS_HPP
#define CRYPTO3_PUBKEY_FELDMAN_SSS_HPP

#include <nil/crypto3/pubkey/secret_sharing/shamir.hpp>

#include <nil/crypto3/pubkey/operations/verify_share_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct feldman_sss : shamir_sss<Group> {
                typedef shamir_sss<Group> base_type;
                typedef typename base_type::group_type group_type;
                typedef typename base_type::basic_policy basic_policy;
                // typedef typename group_type::curve_type::scalar_field_type::integral_type scalar_integral_type;

                //===========================================================================
                // share verification functions

                //
                //  verify public share
                //
                template<typename PublicCoeffs,
                         typename basic_policy::template check_public_elements_t<PublicCoeffs> = true>
                static inline bool verify_share(const PublicCoeffs &public_coeffs,
                                                const typename basic_policy::public_share_t &public_share) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));

                    return verify_share(public_coeffs.begin(), public_coeffs.end(), public_share);
                }

                template<typename PublicCoeffsIt,
                         typename basic_policy::template check_public_element_iterator_t<PublicCoeffsIt> = true>
                static inline bool verify_share(PublicCoeffsIt first, PublicCoeffsIt last,
                                                const typename basic_policy::public_share_t &public_share) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicCoeffsIt>));
                    assert(basic_policy::check_participant_index(public_share.first));
                    assert(basic_policy::check_minimal_size(std::distance(first, last)));

                    typename basic_policy::private_element_t e_i(public_share.first);
                    typename basic_policy::private_element_t temp_mul = basic_policy::private_element_t::one();
                    typename basic_policy::public_element_t verification_val = basic_policy::public_element_t::zero();

                    for (auto it = first; it != last; it++) {
                        verification_val = verification_val + *it * temp_mul;
                        temp_mul = temp_mul * e_i;
                    }
                    return public_share.second == verification_val;
                }

                //
                //  verify private share
                //
                template<typename PublicCoeffs,
                         typename basic_policy::template check_public_elements_t<PublicCoeffs> = true>
                static inline bool verify_share(const PublicCoeffs &public_coeffs,
                                                const typename basic_policy::share_t &share) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));

                    return verify_share(public_coeffs, basic_policy::get_public_share(share));
                }

                //
                //  partial computing of verification value
                //
                static inline typename basic_policy::public_share_t partial_eval_verification_value(
                    const typename basic_policy::public_share_t &init_verification_value,
                    const typename basic_policy::public_coeff_t &public_coeff,
                    std::size_t exp) {
                    assert(basic_policy::check_participant_index(init_verification_value.first));
                    assert(basic_policy::check_exp(exp));

                    return typename basic_policy::public_share_t(
                        init_verification_value.first,
                        init_verification_value.second +
                            typename basic_policy::private_element_t(init_verification_value.first).pow(exp) *
                                public_coeff);
                }
            };

            template<typename Group>
            struct deal_shares_op<feldman_sss<Group>> : public deal_shares_op<shamir_sss<Group>> {
                typedef feldman_sss<Group> scheme_type;
            };

            template<typename Group>
            struct verify_share_op<feldman_sss<Group>> {
                typedef feldman_sss<Group> scheme_type;
                typedef typename scheme_type::basic_policy basic_policy;

                typedef typename scheme_type::group_type group_type;

                typedef typename basic_policy::public_share_t internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t i) {
                    acc.first = i;
                    acc.second = basic_policy::public_element_t::zero();
                }

                static inline void update(internal_accumulator_type &acc,
                                          const typename basic_policy::public_coeff_t &public_coeff, std::size_t exp) {
                    acc.second = scheme_type::partial_eval_verification_value(acc, public_coeff, exp).second;
                }

                static inline bool process(const internal_accumulator_type &acc,
                                           const typename basic_policy::public_share_t &public_share) {
                    return acc == public_share;
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<feldman_sss<Group>> : public reconstruct_secret_op<shamir_sss<Group>> {
                typedef feldman_sss<Group> scheme_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_FELDMAN_SSS_HPP

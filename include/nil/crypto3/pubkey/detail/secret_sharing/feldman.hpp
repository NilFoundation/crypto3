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

#ifndef CRYPTO3_PUBKEY_FELDMAN_SSS_HPP
#define CRYPTO3_PUBKEY_FELDMAN_SSS_HPP

#include <nil/crypto3/pubkey/detail/secret_sharing/shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Group>
                struct feldman_sss : shamir_sss<Group> {
                    typedef shamir_sss<Group> base_type;

                    typedef typename base_type::private_element_type private_element_type;
                    typedef typename base_type::public_element_type public_element_type;

                    typedef typename base_type::share_type share_type;
                    typedef typename base_type::public_share_type public_share_type;
                    typedef typename base_type::public_coeff_type public_coeff_type;

                    //===========================================================================
                    // share verification functions

                    //
                    //  verify public share
                    //
                    template<typename PublicCoeffs, typename base_type::template check_public_element_type<
                                                        typename PublicCoeffs::value_type> = true>
                    static inline bool verify_share(const PublicCoeffs &public_coeffs,
                                                    const public_share_type &public_share) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));
                        assert(base_type::check_participant_index(public_share.first));
                        assert(base_type::check_minimal_size(std::distance(public_coeffs.begin(), public_coeffs.end())));

                        private_element_type e_i(public_share.first);
                        private_element_type temp_mul = private_element_type::one();
                        public_element_type verification_val = public_element_type::zero();

                        for (const auto &c : public_coeffs) {
                            verification_val = verification_val + c * temp_mul;
                            temp_mul = temp_mul * e_i;
                        }
                        return public_share.second == verification_val;
                    }

                    //
                    //  verify private share
                    //
                    template<typename PublicCoeffs, typename base_type::template check_public_element_type<
                                                        typename PublicCoeffs::value_type> = true>
                    static inline bool verify_share(const PublicCoeffs &public_coeffs, const share_type &share) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));
                        return verify_share(public_coeffs, base_type::get_public_share(share));
                    }

                    //
                    //  partial computing of verification value
                    //
                    template<typename Number, typename base_type::template check_number_type<Number> = true>
                    static inline public_share_type
                        partial_eval_verification_value(const public_coeff_type &public_coeff, Number exp,
                                                        const public_share_type &init_verification_value) {
                        assert(base_type::check_participant_index(init_verification_value.first));
                        assert(base_type::check_exp(exp));
                        return public_share_type(init_verification_value.first,
                                                 init_verification_value.second +
                                                     private_element_type(init_verification_value.first).pow(exp) *
                                                         public_coeff);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_FELDMAN_SSS_HPP

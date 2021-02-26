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
                    typedef typename base_type::indexed_private_element_type indexed_private_element_type;
                    typedef typename base_type::indexed_public_element_type indexed_public_element_type;

                    //===========================================================================
                    // share verification functions

                    //
                    //  verify public share
                    //
                    template<typename PublicCoeffs, typename Number,
                             typename std::enable_if<
                                 std::is_same<public_element_type, typename PublicCoeffs::value_type>::value &&
                                     std::is_integral<Number>::value,
                                 bool>::type = true>
                    static inline bool verify_share(const public_element_type &gs_i, Number i,
                                                    const PublicCoeffs &public_coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));
                        assert(base_type::check_participant_index(i));

                        private_element_type e_i(i);
                        private_element_type temp_mul = private_element_type::one();
                        public_element_type temp_s_i = public_element_type::zero();

                        for (const auto &c : public_coeffs) {
                            temp_s_i = temp_s_i + c * temp_mul;
                            temp_mul = temp_mul * e_i;
                        }
                        return gs_i == temp_s_i;
                    }

                    //
                    //  verify private share
                    //
                    template<typename PublicCoeffs, typename Number,
                             typename std::enable_if<
                                 std::is_same<public_element_type, typename PublicCoeffs::value_type>::value &&
                                     std::is_integral<Number>::value,
                                 bool>::type = true>
                    static inline bool verify_share(const private_element_type &s_i, Number i,
                                                    const PublicCoeffs &public_coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));

                        return verify_share(base_type::get_public_element(s_i), i, public_coeffs);
                    }

                    //
                    //  verify indexed public share
                    //
                    template<
                        typename IndexedPublicElement, typename PublicCoeffs,
                        typename base_type::template check_indexed_public_element_type<IndexedPublicElement> = true,
                        typename std::enable_if<
                            std::is_same<public_element_type, typename PublicCoeffs::value_type>::value, bool>::type =
                            true>
                    static inline bool verify_share(const IndexedPublicElement &s_i,
                                                    const PublicCoeffs &public_coeffs) {
                        return verify_share(s_i.second, s_i.first, public_coeffs);
                    }

                    //
                    //  verify indexed private share
                    //
                    template<
                        typename IndexedPrivateElement, typename PublicCoeffs,
                        typename base_type::template check_indexed_private_element_type<IndexedPrivateElement> = true,
                        typename std::enable_if<
                            std::is_same<public_element_type, typename PublicCoeffs::value_type>::value, bool>::type =
                            true>
                    static inline bool verify_share(const IndexedPrivateElement &s_i,
                                                    const PublicCoeffs &public_coeffs) {
                        return verify_share(s_i.second, s_i.first, public_coeffs);
                    }

                    //
                    //  partial computing of verification value
                    //
                    template<
                        typename Number1, typename Number2,
                        typename std::enable_if<std::is_integral<Number1>::value && std::is_integral<Number2>::value,
                                                bool>::type = true>
                    static inline public_element_type eval_partial_verification_value(
                        const public_element_type &public_coeff, Number1 i, Number2 k,
                        const public_element_type &init_value = public_element_type::zero()) {
                        assert(base_type::check_participant_index(i));
                        return init_value + public_coeff * private_element_type(i).pow(k);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_FELDMAN_SSS_HPP

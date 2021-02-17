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

#ifndef CRYPTO3_PUBKEY_FELDMAN_SCHEME_HPP
#define CRYPTO3_PUBKEY_FELDMAN_SCHEME_HPP

#include <nil/crypto3/pubkey/detail/secret_sharing/shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename Group>
                struct feldman_scheme : shamir_scheme<Group> {
                    typedef shamir_scheme<Group> base_type;

                    typedef typename base_type::group_type group_type;
                    typedef typename base_type::base_field_type base_field_type;
                    typedef typename base_type::scalar_field_type scalar_field_type;

                    typedef typename base_type::group_value_type group_value_type;
                    typedef typename base_type::base_field_value_type base_field_value_type;
                    typedef typename base_type::scalar_field_value_type scalar_field_value_type;

                    template<typename Number, typename PublicCoeffsRange,
                             typename std::enable_if<
                                 std::is_same<group_value_type, typename PublicCoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline bool verify_share(const scalar_field_value_type &s_i, const Number &i,
                                                    const PublicCoeffsRange &public_coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffsRange>));

                        return verify_share(base_type::get_public_share(s_i), i, public_coeffs);
                    }

                    template<typename Number, typename PublicCoeffsRange,
                             typename std::enable_if<
                                 std::is_same<group_value_type, typename PublicCoeffsRange::value_type>::value,
                                 bool>::type = true>
                    static inline bool verify_share(const group_value_type &gs_i, const Number &i,
                                                    const PublicCoeffsRange &public_coeffs) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffsRange>));

                        scalar_field_value_type e_i(i);
                        scalar_field_value_type temp_mul = scalar_field_value_type::one();
                        group_value_type temp_s_i = group_value_type::zero();

                        for (const auto &c : public_coeffs) {
                            temp_s_i = temp_s_i + c * temp_mul;
                            temp_mul = temp_mul * e_i;
                        }
                        return gs_i == temp_s_i;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_FELDMAN_SCHEME_HPP

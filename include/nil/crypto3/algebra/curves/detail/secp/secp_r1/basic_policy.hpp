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

#ifndef CRYPTO3_ALGEBRA_CURVES_SECP_R1_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_SECP_R1_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/secp/secp_r1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /**
                     * @brief A struct representing details about base and scalar fields.
                     *
                     * @tparam Version version of the curve
                     */
                    template<std::size_t Version>
                    struct secp_r1_basic_policy;

                    /**
                     * @brief A struct representing details about base and scalar fields of the size 256 bits.
                     */
                    template<>
                    struct secp_r1_basic_policy<256> {
                        constexpr static const std::size_t version = 256;
                        typedef fields::secp_r1_fq<version> g1_field_type;
                        using base_field_type = g1_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus =
                            base_field_type::modulus;    ///< characteristic of the base field

                        typedef fields::secp_r1_fr<version> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus =
                            scalar_field_type::modulus;    ///< characteristic of the scalar field (order of the group
                                                           ///< of points)

                        constexpr static const number_type p =
                            base_field_modulus;    ///< characteristic of the base field
                        constexpr static const number_type q =
                            scalar_field_modulus;    ///< characteristic of the scalar field (order of the group of
                                                     ///< points)

                        constexpr static const number_type a = number_type(
                            0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc_cppui256);    ///< coefficient
                                                                                                             ///< of
                                                                                                             ///< short
                                                                                                             ///< Weierstrass
                                                                                                             ///< curve
                                                                                                             ///< $y^2=x^3+a*x+b$
                        constexpr static const number_type b = number_type(
                            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_cppui256);    ///< coefficient
                                                                                                             ///< of
                                                                                                             ///< short
                                                                                                             ///< Weierstrass
                                                                                                             ///< curve
                                                                                                             ///< $y^2=x^3+a*x+b$

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_zero_fill = {
                            g1_field_type::value_type::zero(), g1_field_type::value_type::one(),
                            g1_field_type::value_type::zero()};

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                            typename g1_field_type::value_type(
                                0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_cppui256),
                            typename g1_field_type::value_type(
                                0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_cppui256),
                            g1_field_type::value_type::one()};
                    };

                    constexpr typename secp_r1_basic_policy<256>::number_type const secp_r1_basic_policy<256>::a;
                    constexpr typename secp_r1_basic_policy<256>::number_type const secp_r1_basic_policy<256>::b;

                    constexpr typename secp_r1_basic_policy<256>::number_type const secp_r1_basic_policy<256>::p;
                    constexpr typename secp_r1_basic_policy<256>::number_type const secp_r1_basic_policy<256>::q;

                    constexpr std::array<typename secp_r1_basic_policy<256>::g1_field_type::value_type, 3> const
                        secp_r1_basic_policy<256>::g1_zero_fill;
                    constexpr std::array<typename secp_r1_basic_policy<256>::g1_field_type::value_type, 3> const
                        secp_r1_basic_policy<256>::g1_one_fill;
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SECP_R1_BASIC_POLICY_HPP

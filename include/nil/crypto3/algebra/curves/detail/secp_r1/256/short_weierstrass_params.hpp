//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_SHORT_WEIERSTRASS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_SHORT_WEIERSTRASS_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/secp_r1/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<>
                    struct secp_r1_params<256, forms::short_weierstrass> {

                        using base_field_type = typename secp_r1_types<256>::base_field_type;
                        using scalar_field_type = typename secp_r1_types<256>::scalar_field_type;

                        constexpr static const typename secp_r1_types<256>::integral_type a =
                            typename secp_r1_types<256>::integral_type(
                            0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc_cppui256);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename secp_r1_types<256>::integral_type b = 
                            typename secp_r1_types<256>::integral_type(
                            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_cppui256);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<256, forms::short_weierstrass> : 
                            public secp_r1_params<256, forms::short_weierstrass> {

                        using field_type = typename secp_r1_types<256>::g1_field_type;
                        
                        template<typename Coordinates>
                        using group_type = secp_r1_types<256>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_cppui256),
                            typename field_type::value_type(
                                0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_cppui256)};
                    };

                    constexpr typename secp_r1_types<256>::integral_type const secp_r1_params<256, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_types<256>::integral_type const secp_r1_params<256, forms::short_weierstrass>::b;

                    constexpr std::array<typename secp_r1_g1_params<256, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<256, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<typename secp_r1_g1_params<256, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_r1_g1_params<256, forms::short_weierstrass>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_SHORT_WEIERSTRASS_PARAMS_HPP

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

#ifndef CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_PARAMS_HPP

#include <nil/crypto3/algebra/curves/detail/secp/secp_r1/basic_params.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t Version, 
                             typename Form>
                    struct secp_r1_params;

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct secp_r1_g1_params;

                    template<>
                    struct secp_r1_params<256, forms::short_weierstrass> : public secp_r1_basic_params<256> {

                        using base_field_type = typename secp_r1_basic_params<256>::base_field_type;
                        using scalar_field_type = typename secp_r1_basic_params<256>::scalar_field_type;

                        constexpr static const typename base_field_type::modulus_type a =
                            typename base_field_type::modulus_type(
                            0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc_cppui256);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename base_field_type::modulus_type b = 
                            typename base_field_type::modulus_type(
                            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b_cppui256);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_r1_g1_params<256, forms::short_weierstrass, 
                        coordinates<forms::short_weierstrass>::projective> : 
                            public secp_r1_params<256, forms::short_weierstrass> {

                        using field_type = typename secp_r1_basic_params<256>::g1_field_type;
                        using group_type = secp_r1_g1<256, forms::short_weierstrass,  
                            coordinates<forms::short_weierstrass>::projective>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one(),
                            field_type::value_type::zero()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296_cppui256),
                            typename field_type::value_type(
                                0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_cppui256),
                            field_type::value_type::one()};
                    };

                    constexpr typename secp_r1_params<256, forms::short_weierstrass>::base_field_type::modulus_type const secp_r1_params<256, forms::short_weierstrass>::a;
                    constexpr typename secp_r1_params<256, forms::short_weierstrass>::base_field_type::modulus_type const secp_r1_params<256, forms::short_weierstrass>::b;

                    constexpr std::array<typename secp_r1_g1_params<256, forms::short_weierstrass, 
                        coordinates<forms::short_weierstrass>::projective>::field_type::value_type, 3> const
                        secp_r1_g1_params<256, forms::short_weierstrass, 
                            coordinates<forms::short_weierstrass>::projective>::zero_fill;
                    constexpr std::array<typename secp_r1_g1_params<256, forms::short_weierstrass, 
                        coordinates<forms::short_weierstrass>::projective>::field_type::value_type, 3> const
                        secp_r1_g1_params<256, forms::short_weierstrass, 
                            coordinates<forms::short_weierstrass>::projective>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_SECP_R1_256_PARAMS_HPP

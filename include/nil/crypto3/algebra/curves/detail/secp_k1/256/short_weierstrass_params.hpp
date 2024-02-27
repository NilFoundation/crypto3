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

#ifndef CRYPTO3_ALGEBRA_CURVES_SECP_K1_256_SHORT_WEIERSTRASS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_SECP_K1_256_SHORT_WEIERSTRASS_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/secp_k1/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<>
                    struct secp_k1_params<160, forms::short_weierstrass> {

                        using base_field_type = typename secp_k1_types<160>::base_field_type;
                        using scalar_field_type = typename secp_k1_types<160>::scalar_field_type;

                        constexpr static const typename secp_k1_types<160>::integral_type a =
                            typename secp_k1_types<160>::integral_type(
                                0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename secp_k1_types<160>::integral_type b =
                            typename secp_k1_types<160>::integral_type(
                                0x07);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_k1_g1_params<160, forms::short_weierstrass>
                        : public secp_k1_params<160, forms::short_weierstrass> {

                        using field_type = typename secp_k1_types<160>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_k1_types<160>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb_cppui160),
                            typename field_type::value_type(0x938cf935318fdced6bc28286531733c3f03c4fee_cppui160)};
                    };

                    constexpr typename secp_k1_types<160>::integral_type const
                        secp_k1_params<160, forms::short_weierstrass>::a;
                    constexpr typename secp_k1_types<160>::integral_type const
                        secp_k1_params<160, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_k1_g1_params<160, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<160, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_k1_g1_params<160, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<160, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_k1_params<192, forms::short_weierstrass> {

                        using base_field_type = typename secp_k1_types<192>::base_field_type;
                        using scalar_field_type = typename secp_k1_types<192>::scalar_field_type;

                        constexpr static const typename secp_k1_types<192>::integral_type a =
                            typename secp_k1_types<192>::integral_type(
                                0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename secp_k1_types<192>::integral_type b =
                            typename secp_k1_types<192>::integral_type(
                                0x3);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_k1_g1_params<192, forms::short_weierstrass>
                        : public secp_k1_params<192, forms::short_weierstrass> {

                        using field_type = typename secp_k1_types<192>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_k1_types<192>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d_cppui192),
                            typename field_type::value_type(
                                0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d_cppui192)};
                    };

                    constexpr typename secp_k1_types<192>::integral_type const
                        secp_k1_params<192, forms::short_weierstrass>::a;
                    constexpr typename secp_k1_types<192>::integral_type const
                        secp_k1_params<192, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_k1_g1_params<192, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<192, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_k1_g1_params<192, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<192, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_k1_params<224, forms::short_weierstrass> {

                        using base_field_type = typename secp_k1_types<224>::base_field_type;
                        using scalar_field_type = typename secp_k1_types<224>::scalar_field_type;

                        constexpr static const typename secp_k1_types<224>::integral_type a =
                            typename secp_k1_types<224>::integral_type(
                                0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename secp_k1_types<224>::integral_type b =
                            typename secp_k1_types<224>::integral_type(
                                0x5);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_k1_g1_params<224, forms::short_weierstrass>
                        : public secp_k1_params<224, forms::short_weierstrass> {

                        using field_type = typename secp_k1_types<224>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_k1_types<224>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c_cppui224),
                            typename field_type::value_type(
                                0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5_cppui224)};
                    };

                    constexpr typename secp_k1_types<224>::integral_type const
                        secp_k1_params<224, forms::short_weierstrass>::a;
                    constexpr typename secp_k1_types<224>::integral_type const
                        secp_k1_params<224, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_k1_g1_params<224, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<224, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_k1_g1_params<224, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<224, forms::short_weierstrass>::one_fill;

                    template<>
                    struct secp_k1_params<256, forms::short_weierstrass> {

                        using base_field_type = typename secp_k1_types<256>::base_field_type;
                        using scalar_field_type = typename secp_k1_types<256>::scalar_field_type;

                        constexpr static const typename secp_k1_types<256>::integral_type a =
                            typename secp_k1_types<256>::integral_type(
                                0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename secp_k1_types<256>::integral_type b =
                            typename secp_k1_types<256>::integral_type(
                                0x07);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct secp_k1_g1_params<256, forms::short_weierstrass>
                        : public secp_k1_params<256, forms::short_weierstrass> {

                        using field_type = typename secp_k1_types<256>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = secp_k1_types<256>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_cppui256),
                            typename field_type::value_type(
                                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_cppui256)};
                    };

                    constexpr typename secp_k1_types<256>::integral_type const
                        secp_k1_params<256, forms::short_weierstrass>::a;
                    constexpr typename secp_k1_types<256>::integral_type const
                        secp_k1_params<256, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename secp_k1_g1_params<256, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<256, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename secp_k1_g1_params<256, forms::short_weierstrass>::field_type::value_type, 2> const
                        secp_k1_g1_params<256, forms::short_weierstrass>::one_fill;
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_SECP_K1_256_SHORT_WEIERSTRASS_PARAMS_HPP
